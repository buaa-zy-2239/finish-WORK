#!/usr/bin/env python3
"""
统一蜂群场景实验：
- 单一试验场景（固定网络/ZSP/信道/统计口径）
- 可插拔运动源：
  1) trace_dataset   : 轨迹模板数据集回放
  2) task_random     : 任务驱动 + 随机化（可复现 seed）
"""

from __future__ import annotations

import argparse
import copy
import gc
import json
import math
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]

# Gauss–Markov 3D 机动应力档位（仅影响 GM 参数；丢包仍由信道/RSSI/burst 模型驱动）
GM3D_STRESS_PRESETS: Dict[str, Dict[str, float]] = {
    "conservative": {
        "alpha": 0.88,
        "mean_speed_mps": 3.0,
        "speed_std_mps": 2.0,
    },
    "nominal": {
        "alpha": 0.7,
        "mean_speed_mps": 5.0,
        "speed_std_mps": 5.0,
    },
    "aggressive": {
        "alpha": 0.45,
        "mean_speed_mps": 12.0,
        "speed_std_mps": 7.0,
    },
}
DEFAULT_NS3 = os.environ.get("NS3_BIN", "/home/zhang/ns/ns-allinone-3.43/ns-3.43/ns3")
DEFAULT_SIM = os.environ.get("SIMULATOR", str(ROOT / "simulator_builder.py"))


# 轨迹模板数据集（时间, [x,y,z]）
TRACE_DATASET: List[List[List[float]]] = [
    [[0, [-180, -80, 55]], [12, [-60, -60, 55]], [24, [80, -40, 55]], [36, [170, -20, 55]]],
    [[0, [-170, -30, 55]], [12, [-50, -20, 55]], [24, [70, 0, 55]], [36, [180, 15, 55]]],
    [[0, [-175, 20, 55]], [12, [-55, 30, 55]], [24, [65, 45, 55]], [36, [175, 60, 55]]],
    [[0, [-165, 70, 55]], [12, [-45, 85, 55]], [24, [75, 95, 55]], [36, [185, 110, 55]]],
]

# 学术对齐信道预设（用于提升实验可说服力）
# - INFOCOM'11 (Yanmaz et al.): open field/campus 对数距离模型拟合（PLE 约 2.2 / 2.5~2.6）
# - VTC measurement-based A2G model: 阴影方差约 4.9~5.8 dB，可映射到更激进的边缘丢包
ACADEMIC_CHANNEL_PROFILES: Dict[str, Dict[str, Any]] = {
    "infocom11_open_field": {
        "citation": "Yanmaz et al., INFOCOM Workshops 2011",
        "model": "log_distance_rssi_loss",
        "params": {
            "rssi_good_dbm": -64.0,
            "rssi_bad_dbm": -89.0,
            "loss_good": 0.01,
            "loss_bad": 0.35,
            "burst": {
                "p_good_to_bad": 0.02,
                "p_bad_to_good": 0.30,
                "loss_good": 0.01,
                "loss_bad": 0.70,
            },
        },
    },
    "infocom11_campus": {
        "citation": "Yanmaz et al., INFOCOM Workshops 2011",
        "model": "log_distance_rssi_loss",
        "params": {
            "rssi_good_dbm": -67.0,
            "rssi_bad_dbm": -92.0,
            "loss_good": 0.03,
            "loss_bad": 0.45,
            "burst": {
                "p_good_to_bad": 0.03,
                "p_bad_to_good": 0.24,
                "loss_good": 0.02,
                "loss_bad": 0.76,
            },
        },
    },
    "vtc_a2g_shadowing": {
        "citation": "VTC low-altitude UAV access channel measurements",
        "model": "log_distance_rssi_loss_with_shadowing_proxy",
        "params": {
            "rssi_good_dbm": -66.0,
            "rssi_bad_dbm": -94.0,
            "loss_good": 0.04,
            "loss_bad": 0.55,
            "burst": {
                "p_good_to_bad": 0.04,
                "p_bad_to_good": 0.20,
                "loss_good": 0.03,
                "loss_bad": 0.82,
            },
        },
    },
    "twc2025_elevation_aware": {
        "citation": "Ultra-Wideband Nonstationary Channel Modeling for UAV-to-Ground Communications, IEEE TWC 2025; Elevation-Aware Large-Scale Channel Model, Mathematics 2025",
        "model": "elevation_aware_kfactor_nakagami",
        "params": {
            "rssi_good_dbm": -55.0,  # better LOS at high elevation
            "rssi_bad_dbm": -85.0,
            "loss_good": 0.005,
            "loss_bad": 0.25,
            "burst": {
                "p_good_to_bad": 0.015,
                "p_bad_to_good": 0.35,
                "loss_good": 0.01,
                "loss_bad": 0.45,
            },
        },
    },
}


def _resolve_academic_profile(profile: str) -> Dict[str, Any]:
    key = (profile or "").strip().lower().replace("-", "_")
    if not key:
        raise ValueError(
            "academic profile is required (e.g. --academic-profile infocom11_open_field)"
        )
    if key not in ACADEMIC_CHANNEL_PROFILES:
        allowed = ", ".join(sorted(ACADEMIC_CHANNEL_PROFILES.keys()))
        raise ValueError(f"unknown academic profile '{profile}', allowed: {allowed}")
    return ACADEMIC_CHANNEL_PROFILES[key]


def _analyze_log_dir(log_dir: str) -> Dict[str, Any]:
    sys.path.insert(0, str(ROOT / "Backend"))
    from analysis.protocol_analyzer import D2ZAnalyzer  # noqa: E402
    from core.event_models import D2ZPhase  # noqa: E402
    from core.log_parser import D2ZLogParser  # noqa: E402

    events = D2ZLogParser.parse_all_logs(log_dir)
    D2ZLogParser.enrich_auth_session_ids(events)
    analyzer = D2ZAnalyzer(events)
    summary = analyzer.get_summary()
    by_uav: Dict[int, Dict[str, int]] = {}
    for s in analyzer.sessions.values():
        uid = s.uav_id
        if uid is None or uid < 0:
            continue
        b = by_uav.setdefault(uid, {"sessions": 0, "successful": 0})
        b["sessions"] += 1
        if s.success:
            b["successful"] += 1
    # 口径：重试属于同一会话，不新增 initiated_sessions
    initiated = sum(
        1
        for e in events
        if (
            e.phase == D2ZPhase.INITIATED
            and (e.uav_id is not None and e.uav_id >= 0)
            and "RETRY" not in (e.protocol_step or "").upper()
        )
    )
    closed = len(analyzer.sessions)
    return {
        "event_count": len(events),
        "session_count": len(analyzer.sessions),
        "initiated_sessions": initiated,
        "closed_sessions": closed,
        "pending_sessions": max(0, initiated - closed),
        "analyzer_summary": summary,
        "per_uav": by_uav,
    }


def _prepare_log_dir(log_dir: Path) -> None:
    if log_dir.exists():
        shutil.rmtree(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)


def _write_manifest(out_root: Path, runs: List[Dict[str, Any]]) -> None:
    with open(out_root / "swarm_manifest.json", "w", encoding="utf-8") as f:
        json.dump(
            {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "runs": runs},
            f,
            indent=2,
            default=str,
        )


def _dataset_waypoints(uid: int) -> List[List[float]]:
    tpl = TRACE_DATASET[uid % len(TRACE_DATASET)]
    row = uid // 10
    col = uid % 10
    dx = col * 8.0
    dy = row * 10.0
    return [[float(t), [float(p[0]) + dx, float(p[1]) + dy, float(p[2])]] for t, p in tpl]


def _distance_3d(a: List[float], b: List[float]) -> float:
    dx = float(a[0]) - float(b[0])
    dy = float(a[1]) - float(b[1])
    dz = float(a[2]) - float(b[2])
    return math.sqrt(dx * dx + dy * dy + dz * dz)


def estimate_link_lifetime(motion_mode: str, n_uavs: int, density: float) -> float:
    """
    估算链路持续时间（基于移动模型和密度）
    参考: "Topology Dynamics in UAV Networks" IEEE TMC 2023
    """
    base_lifetime = 30.0  # 基础链路持续时间（秒）

    # 移动模型影响
    mobility_factor = {
        "trace_dataset": 1.0,      # 轨迹数据：中等动态性
        "task_random": 0.7,         # 任务驱动：较高动态性
        "gauss_markov_3d": 0.5,     # GM3D：高动态性（连续速度变化）
    }.get(motion_mode, 0.8)

    # 密度影响：密度越高，UAV越近，链路越稳定
    if density > 0:
        density_factor = min(2.0, max(0.5, 10.0 / density))
    else:
        density_factor = 1.0

    # 规模影响：规模越大，相对移动机会越多
    scale_factor = 1.0 / (1.0 + (n_uavs / 200))

    return round(base_lifetime * mobility_factor * density_factor * scale_factor, 1)


def estimate_handover_rate(n_zsps: int, n_uavs: int, density: float) -> float:
    """
    估算ZSP切换率（次/分钟/UAV）
    基于覆盖重叠区域和移动速度估算
    """
    if n_zsps <= 1:
        return 0.0

    # 每个ZSP覆盖的UAV数量
    uavs_per_zsp = n_uavs / n_zsps

    # 密度影响区域大小
    if density > 0:
        area_per_zsp_km2 = uavs_per_zsp / density
        coverage_radius_m = (area_per_zsp_km2 ** 0.5) * 500  # 假设六边形覆盖
    else:
        coverage_radius_m = 1000  # 默认1km覆盖

    # 平均移动速度15m/s，穿越覆盖边缘的频率
    avg_speed_mps = 15.0
    boundary_width_m = 100  # 切换决策边界宽度

    # 估算穿越边界的频率
    crossing_time_s = (coverage_radius_m * 2) / avg_speed_mps
    handover_prob = boundary_width_m / (coverage_radius_m * 2)

    # 每分钟切换率
    handover_per_min = (60.0 / crossing_time_s) * handover_prob

    return round(handover_per_min, 2)


def classify_topology_dynamicity(motion_mode: str, n_uavs: int, density: float) -> str:
    """
    根据移动模型和网络参数分类拓扑动态性级别
    参考: FANET mobility classification (ACM MobiHoc 2024)
    """
    # 计算预期链路变化率
    link_lifetime = estimate_link_lifetime(motion_mode, n_uavs, density)
    link_change_rate = 1.0 / link_lifetime  # 每秒链路变化率

    # 归一化到每个UAV
    normalized_rate = link_change_rate / max(1, n_uavs / 10)

    if normalized_rate < 0.02:
        return "low"      # < 0.02 link/s/UAV
    elif normalized_rate < 0.1:
        return "medium"   # 0.02-0.1 link/s/UAV
    else:
        return "high"     # > 0.1 link/s/UAV


def _task_waypoints(uid: int, seed: int, max_speed_mps: float = 22.0) -> List[List[float]]:
    """
    任务驱动随机轨迹（可复现）：
    - 先随机采样候选任务点
    - 按最大速度约束反推最小飞行时长，保证轨迹物理可达
    """
    rng = random.Random(seed * 1_000_003 + uid * 97)
    row = uid // 10
    col = uid % 10
    x = -150.0 + col * 14.0
    y = -80.0 + row * 16.0
    z = 55.0
    waypoints: List[List[float]] = [[0.0, [x, y, z]]]
    t = 6.0
    current = [x, y, z]
    speed = max(1.0, float(max_speed_mps))
    for _ in range(3):
        tx = rng.uniform(-40, 190)
        ty = rng.uniform(-130, 130)
        target = [round(tx, 2), round(ty, 2), z]
        # 任务执行/重规划造成的停留时间（可调）
        dwell_s = rng.uniform(2.0, 5.0)
        min_flight_s = _distance_3d(current, target) / speed
        dt = max(min_flight_s + dwell_s, 1.0)
        t += dt
        waypoints.append([round(t, 2), target])
        current = target
    return waypoints


def build_unified_config(
    size: int,
    protocol: str,
    motion_mode: str,
    seed: int,
    uplink_loss_rate: float = 0.0,
    downlink_loss_rate: float = 0.0,
    d2z_ack_timeout_s: float = 1.5,  # 优化：正常认证<1s，1.5s足够覆盖延迟
    max_d2z_attempts: int = 2,
    desync_template: str = "",
    desync_multi_round: bool = False,
    desync_boundary_recovery: bool = False,
    retry_d2z_after_intercept_s: float = 2.0,
    rssi_loss_enabled: bool = False,
    rssi_good_dbm: float = -65.0,
    rssi_bad_dbm: float = -90.0,
    rssi_loss_good: float = 0.0,
    rssi_loss_bad: float = 0.5,
    academic_profile: str = "",
    burst_loss_enabled: bool = False,
    burst_p_good_to_bad: float = 0.02,
    burst_p_bad_to_good: float = 0.25,
    burst_loss_good: float = 0.01,
    burst_loss_bad: float = 0.75,
    density_uavs_per_km2: float = 0.0,  # 0表示不使用密度模型
    gm3d_stress: str = "nominal",  # conservative|nominal|aggressive（仅 gauss_markov_3d）
    reauth_rounds: int = 3,
    reauth_spacing_s: float = 24.0,
    desync_attack_min_completed_sessions: Optional[int] = None,
    desync_attack_max_completed_sessions: Optional[int] = None,
) -> Dict[str, Any]:
    if size < 1:
        raise ValueError("size must be >= 1")
    if motion_mode not in ("trace_dataset", "task_random", "gauss_markov_3d"):
        raise ValueError(f"unsupported motion mode: {motion_mode}")
    profile_meta = _resolve_academic_profile(academic_profile)
    profile_params = profile_meta["params"]
    burst_profile = profile_params.get("burst") or {}

    trigger_start = 8.0
    trigger_spread = 14.0 if size <= 50 else 22.0
    uavs: List[Dict[str, Any]] = []

    # 首先计算ZSP部署（在UAV循环前定义，供handover配置使用）
    area_config = {}
    if density_uavs_per_km2 > 0:
        area_km2 = size / density_uavs_per_km2
        area_side_m = (area_km2 ** 0.5) * 1000  # km -> m
        area_config = {
            "density_uavs_per_km2": density_uavs_per_km2,
            "area_km2": round(area_km2, 2),
            "area_side_m": round(area_side_m, 1),
            "scenario_type": "density_based",
        }
        # 多ZSP部署：每25个UAV一个ZSP（网格布局）
        n_zsps = max(1, (size + 24) // 25)  # 向上取整
        zsps = []
        if n_zsps == 1:
            zsps = [{"id": size + 1, "position": [0, 0, 100]}]
        else:
            # 网格布局ZSP
            grid_size = int(n_zsps ** 0.5)
            spacing_m = area_side_m / (grid_size + 1)
            for i in range(n_zsps):
                row = i // grid_size
                col = i % grid_size
                x = (col + 1) * spacing_m - area_side_m / 2
                y = (row + 1) * spacing_m - area_side_m / 2
                zsps.append({"id": size + 1 + i, "position": [round(x, 1), round(y, 1), 100]})
    else:
        area_side_m = 1000.0  # 默认1km
        zsps = [{"id": size + 1, "position": [0, 0, 100]}]

    # Gauss-Markov 3D移动模型参数（学术标准配置 + 可复现应力档位）
    stress_key = (gm3d_stress or "nominal").strip().lower()
    if stress_key not in GM3D_STRESS_PRESETS:
        stress_key = "nominal"
    gm_stress = GM3D_STRESS_PRESETS[stress_key]
    gm3d_config = {
        "alpha": gm_stress["alpha"],
        "mean_speed_mps": gm_stress["mean_speed_mps"],
        "speed_std_mps": gm_stress["speed_std_mps"],
        "mean_altitude_m": 80.0,
        "altitude_std_m": 20.0 if stress_key != "aggressive" else 28.0,
        "max_speed_mps": 22.0,
        "turn_rate_mean": 0.1,
        "turn_rate_std": 0.05,
        "stress_tier": stress_key,
    }

    max_speed_task_random_mps = 22.0
    for uid in range(size):
        if motion_mode == "trace_dataset":
            waypoints = _dataset_waypoints(uid)
            mobility_config = {"type": "waypoint", "waypoints": waypoints}
        elif motion_mode == "gauss_markov_3d":
            # 真正的Gauss-Markov 3D移动模型：运行时动态速度更新
            gm_seed = seed * 10000 + uid
            rng = random.Random(gm_seed)
            
            # 计算区域边界
            if density_uavs_per_km2 > 0:
                area_km2 = size / density_uavs_per_km2
                area_side_m = (area_km2 ** 0.5) * 1000
            else:
                area_side_m = 1000.0
            
            # 生成随机初始位置（在ZSP附近，确保能建立通信）
            # ZSP位于[0,0,100]，UAV在水平距离100-300m范围内随机分布
            initial_distance = rng.uniform(50, 150)  # 水平距离100-300m
            initial_angle = rng.uniform(0, 2 * math.pi)  # 随机方向
            initial_x = initial_distance * math.cos(initial_angle)
            initial_y = initial_distance * math.sin(initial_angle)
            initial_z = gm3d_config["mean_altitude_m"] + rng.uniform(-10, 10)
            initial_z = max(50.0, min(120.0, initial_z))  # 高度50-120m
            movement_area_size = 600.0  # 600m x 600m 移动区域
            mobility_config = {
                "type": "gauss_markov_3d",
                "seed": gm_seed,
                "alpha": gm3d_config["alpha"],
                "mean_speed_mps": gm3d_config["mean_speed_mps"],
                "speed_std_mps": gm3d_config["speed_std_mps"],
                "mean_altitude_m": gm3d_config["mean_altitude_m"],
                "altitude_std_m": gm3d_config["altitude_std_m"],
                # 关键：区域边界参数（运行时GM3D必需）
                "area_size_x": movement_area_size,
                "area_size_y": movement_area_size,
                "min_altitude_m": 30.0,
                "max_altitude_m": 200.0,
                # 初始位置和速度
                "initial_position": [round(initial_x, 2), round(initial_y, 2), round(initial_z, 2)],
                "initial_velocity": [
                    round(rng.uniform(-gm3d_config["mean_speed_mps"], gm3d_config["mean_speed_mps"]), 2),
                    round(rng.uniform(-gm3d_config["mean_speed_mps"], gm3d_config["mean_speed_mps"]), 2),
                    round(rng.uniform(-2.0, 2.0), 2),
                ],
                "position_update_interval_s": 0.1,  # 10Hz更新（顶会标准）
                # 集群行为参数
                "cluster_behavior": {
                    "enabled": size > 10,
                    "cluster_id": uid // max(1, size // 5),
                    "cohesion_weight": 0.3,
                    "separation_weight": 0.5,
                    "alignment_weight": 0.2,
                },
            }
            # GM3D模式下仍需要初始航点用于可视化参考
            waypoints = _task_waypoints(uid, seed, max_speed_mps=max_speed_task_random_mps)
        else:
            waypoints = _task_waypoints(uid, seed, max_speed_mps=max_speed_task_random_mps)
            mobility_config = {"type": "waypoint", "waypoints": waypoints}

        if size == 1:
            t_auth = trigger_start
        else:
            t_auth = trigger_start + trigger_spread * (uid / (size - 1))

        # 动态ZSP选择配置（信号强度驱动）
        zsp_handover_config = {
            "enabled": len(zsps) > 1,  # 多ZSP时启用切换
            "rssi_threshold_dbm": -85,  # 切换阈值：低于-85dBm触发切换评估
            "hysteresis_db": 5,           # 滞后余量，避免乒乓切换
            "min_dwell_time_s": 2.0,      # 最小停留时间，避免频繁切换
            "handover_delay_s": 0.5,      # 切换执行延迟
            "reauth_after_handover": True, # 切换后重新认证
        }

        uavs.append(
            {
                "id": uid,
                "mobility": mobility_config,
                "auth_trigger": {
                    "initial_on_connect": False,
                    "time_offsets_s": [round(t_auth, 3)],
                    "allow_reauth": False,
                },
                "link_state": {
                    "comm_range_m": 800,
                    "uplink_loss_rate": max(0.0, min(1.0, float(uplink_loss_rate))),
                    "zsp_handover": zsp_handover_config,
                    "rssi_loss_model": {
                        "enabled": bool(rssi_loss_enabled),
                        "rssi_good_dbm": float(
                            profile_params["rssi_good_dbm"] if rssi_loss_enabled else rssi_good_dbm
                        ),
                        "rssi_bad_dbm": float(
                            profile_params["rssi_bad_dbm"] if rssi_loss_enabled else rssi_bad_dbm
                        ),
                        "loss_good": max(
                            0.0,
                            min(
                                1.0,
                                float(profile_params["loss_good"] if rssi_loss_enabled else rssi_loss_good),
                            ),
                        ),
                        "loss_bad": max(
                            0.0,
                            min(
                                1.0,
                                float(profile_params["loss_bad"] if rssi_loss_enabled else rssi_loss_bad),
                            ),
                        ),
                    },
                    "uplink_burst_loss_model": {
                        "enabled": bool(burst_loss_enabled),
                        "p_good_to_bad": float(
                            burst_profile.get("p_good_to_bad", burst_p_good_to_bad)
                            if burst_loss_enabled
                            else burst_p_good_to_bad
                        ),
                        "p_bad_to_good": float(
                            burst_profile.get("p_bad_to_good", burst_p_bad_to_good)
                            if burst_loss_enabled
                            else burst_p_bad_to_good
                        ),
                        "loss_good": max(
                            0.0,
                            min(
                                1.0,
                                float(
                                    burst_profile.get("loss_good", burst_loss_good)
                                    if burst_loss_enabled
                                    else burst_loss_good
                                ),
                            ),
                        ),
                        "loss_bad": max(
                            0.0,
                            min(
                                1.0,
                                float(
                                    burst_profile.get("loss_bad", burst_loss_bad)
                                    if burst_loss_enabled
                                    else burst_loss_bad
                                ),
                            ),
                        ),
                    },
                },
            }
        )

    base_duration = 65.0 if size <= 30 else 95.0
    if motion_mode == "task_random":
        base_duration += 10.0

    desync_on = bool(desync_template and str(desync_template).strip())
    schedule_multi_auth = bool(desync_multi_round or desync_boundary_recovery)
    spacing = max(0.5, float(reauth_spacing_s))
    n_rounds = min(5000, max(1, int(reauth_rounds)))
    if desync_attack_min_completed_sessions is not None:
        min_completed_d2z = max(0, int(desync_attack_min_completed_sessions))
    elif desync_boundary_recovery and schedule_multi_auth and n_rounds > 1 and n_rounds >= 20:
        # 大规模多轮：默认在约一半成功鉴权之后才允许首次拦截（与 first_auth_only = 中段单次扰动）
        min_completed_d2z = max(0, (n_rounds + 1) // 2 - 1)
    else:
        min_completed_d2z = 0

    # 攻击窗口：最大完成会话数（用于持续多轮攻击后恢复的场景）
    if desync_attack_max_completed_sessions is not None:
        max_completed_d2z = max(0, int(desync_attack_max_completed_sessions))
        # 确保max >= min，否则禁用上限
        if max_completed_d2z < min_completed_d2z:
            max_completed_d2z = None
    else:
        max_completed_d2z = None

    if schedule_multi_auth:
        max_last = 0.0
        for u in uavs:
            t0 = float(u["auth_trigger"]["time_offsets_s"][0])
            u["auth_trigger"]["allow_reauth"] = True
            offsets = [round(t0 + j * spacing, 3) for j in range(n_rounds)]
            u["auth_trigger"]["time_offsets_s"] = offsets
            max_last = max(max_last, offsets[-1])
        tail_s = 60.0 if n_rounds <= 20 else min(240.0, 15.0 + 0.05 * n_rounds * spacing)
        base_duration = max(base_duration, max_last + tail_s)

    # 密度计算：根据UAV数量和密度计算仿真区域
    area_config = {}
    if density_uavs_per_km2 > 0:
        area_km2 = size / density_uavs_per_km2
        area_side_m = (area_km2 ** 0.5) * 1000  # km -> m
        area_config = {
            "density_uavs_per_km2": density_uavs_per_km2,
            "area_km2": round(area_km2, 2),
            "area_side_m": round(area_side_m, 1),
            "scenario_type": "density_based",
        }
        # 多ZSP部署：每25个UAV一个ZSP（网格布局）
        n_zsps = max(1, (size + 24) // 25)  # 向上取整
        zsps = []
        if n_zsps == 1:
            zsps = [{"id": size + 1, "position": [0, 0, 100]}]
        else:
            # 网格布局ZSP
            grid_size = int(n_zsps ** 0.5)
            spacing_m = area_side_m / (grid_size + 1)
            for i in range(n_zsps):
                row = i // grid_size
                col = i % grid_size
                x = (col + 1) * spacing_m - area_side_m / 2
                y = (row + 1) * spacing_m - area_side_m / 2
                zsps.append({"id": size + 1 + i, "position": [round(x, 1), round(y, 1), 100]})
    else:
        zsps = [{"id": size + 1, "position": [0, 0, 100]}]

    # 计算拓扑动态性预期指标（用于后续分析对比）
    expected_topology_metrics = {
        "expected_link_lifetime_s": estimate_link_lifetime(motion_mode, size, density_uavs_per_km2),
        "expected_handover_rate_per_min": estimate_handover_rate(len(zsps), size, density_uavs_per_km2) if len(zsps) > 1 else 0,
        "topology_change_classification": classify_topology_dynamicity(motion_mode, size, density_uavs_per_km2),
    }

    return {
        "task_id": f"unified_{motion_mode}_n{size}_{protocol.lower()}_s{seed}",
        "name": f"Unified swarm ({motion_mode}) N={size} {protocol}",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenario": {
            "name": "swarm_unified_single_scenario",
            "motion_mode": motion_mode,
            "gm3d_stress_tier": stress_key if motion_mode == "gauss_markov_3d" else None,
            "seed": seed,
            "max_speed_task_random_mps": max_speed_task_random_mps,
            "uplink_loss_rate": max(0.0, min(1.0, float(uplink_loss_rate))),
            "downlink_loss_rate": max(0.0, min(1.0, float(downlink_loss_rate))),
            "d2z_ack_timeout_s": float(d2z_ack_timeout_s),
            "max_d2z_attempts": int(max_d2z_attempts),
            "desync_template": desync_template,
            "reauth_rounds": n_rounds,
            "reauth_spacing_s": round(spacing, 4),
            "desync_attack_min_completed_sessions": int(min_completed_d2z),
            "desync_attack_max_completed_sessions": int(max_completed_d2z) if max_completed_d2z is not None else None,
            "rssi_loss_enabled": bool(rssi_loss_enabled),
            "burst_loss_enabled": bool(burst_loss_enabled),
            "academic_profile": academic_profile,
            "academic_alignment": {
                "citation": profile_meta["citation"],
                "channel_model": profile_meta["model"],
            },
            "mobility_model_config": gm3d_config if motion_mode == "gauss_markov_3d" else None,
            "topology_dynamics": expected_topology_metrics,
            "zsp_deployment": {
                "count": len(zsps),
                "positions": [z["position"] for z in zsps],
                "handover_enabled": len(zsps) > 1,
            },
            **area_config,  # 合并密度配置
        },
        "duration": base_duration,
        "uavs": uavs,
        "zsps": zsps,
        "simulation": {"duration": base_duration},
        "protocol": protocol,
        "channel": {
            "type": "WiFi",  # 升级到WiFi信道 (支持衰落模型)
            "datarate": "6Mbps",  # 802.11ah典型速率
            "loss_model": "nakagami",  # Nakagami-m衰落 (UAV A2G标准)
            "nakagami_m0": 1.5,  # 近场衰落参数
            "nakagami_m1": 0.75,  # 中场衰落参数
            "nakagami_m2": 0.5,  # 远场衰落参数
        },
        "security_profile": {
            "adversary": "none",
            "attack_model": {
                "downlink_loss_rate": max(0.0, min(1.0, float(downlink_loss_rate))),
                "d2z_ack_timeout_s": float(d2z_ack_timeout_s),
                "max_d2z_attempts": int(max_d2z_attempts),
                "desync_template": desync_template,
                "desync_experiment_enabled": desync_on,
                "desync_multi_round": schedule_multi_auth,
                "desync_boundary_recovery": bool(desync_boundary_recovery),
                "desync_attack_every_round": bool(
                    (desync_multi_round and not desync_boundary_recovery) or max_completed_d2z is not None
                ),  # 攻击窗口模式下启用持续攻击（但仍受max限制）
                "desync_attack_min_completed_sessions": int(min_completed_d2z),
                "desync_attack_max_completed_sessions": int(max_completed_d2z) if max_completed_d2z is not None else None,
                "retry_d2z_after_intercept_s": float(retry_d2z_after_intercept_s),
                "downlink_burst_loss_model": {
                    "enabled": bool(burst_loss_enabled),
                    "p_good_to_bad": float(
                        burst_profile.get("p_good_to_bad", burst_p_good_to_bad)
                        if burst_loss_enabled
                        else burst_p_good_to_bad
                    ),
                    "p_bad_to_good": float(
                        burst_profile.get("p_bad_to_good", burst_p_bad_to_good)
                        if burst_loss_enabled
                        else burst_p_bad_to_good
                    ),
                    "loss_good": max(
                        0.0,
                        min(
                            1.0,
                            float(
                                burst_profile.get("loss_good", burst_loss_good)
                                if burst_loss_enabled
                                else burst_loss_good
                            ),
                        ),
                    ),
                    "loss_bad": max(
                        0.0,
                        min(
                            1.0,
                            float(
                                burst_profile.get("loss_bad", burst_loss_bad)
                                if burst_loss_enabled
                                else burst_loss_bad
                            ),
                        ),
                    ),
                },
            },
        },
    }


def _channel_bank_suffix(args: argparse.Namespace) -> str:
    """区分仅信道/丢包参数不同的冻结场景，避免 scenario_bank 错误复用。"""
    r = bool(getattr(args, "rssi_loss_enabled", False))
    b = bool(getattr(args, "burst_loss_enabled", False))
    try:
        u = float(getattr(args, "uplink_loss_rate", 0.0) or 0.0)
    except (TypeError, ValueError):
        u = 0.0
    if not r and not b and u <= 0.0:
        return ""
    suf = "_ch"
    if u > 0.0:
        suf += f"u{min(999, int(round(1000.0 * u)))}"
    if r:
        suf += "R"
    if b:
        suf += "B"
    return suf


def _scenario_bank_key(
    mode: str,
    size: int,
    seed: int,
    desync_multi_round: bool = False,
    desync_boundary_recovery: bool = False,
    desync_template: str = "",
    density_uavs_per_km2: float = 0.0,
    gm3d_stress: str = "nominal",
    channel_bank_suffix: str = "",
    reauth_rounds: int = 3,
    reauth_spacing_s: float = 24.0,
    desync_attack_min_completed_sessions: Optional[int] = None,
    desync_attack_max_completed_sessions: Optional[int] = None,
) -> str:
    suf = ""
    schedule_mr = bool(desync_multi_round or desync_boundary_recovery)
    if schedule_mr:
        suf += "_mr1"
        rr = max(1, int(reauth_rounds))
        sp = max(0.5, float(reauth_spacing_s))
        if desync_attack_min_completed_sessions is not None:
            mc = max(0, int(desync_attack_min_completed_sessions))
        elif desync_boundary_recovery and rr > 1 and rr >= 20:
            mc = max(0, (rr + 1) // 2 - 1)
        else:
            mc = 0
        suf += f"_rr{min(99999, rr)}_sp{int(round(sp * 100))}_mc{min(99999, mc)}"
        # 攻击窗口上限（用于持续攻击+恢复场景）
        if desync_attack_max_completed_sessions is not None:
            max_c = max(0, int(desync_attack_max_completed_sessions))
            suf += f"_max{min(99999, max_c)}"
    if desync_boundary_recovery:
        suf += "_br1"
    # 关键修复：包含desync_template信息，避免不同攻击类型缓存冲突
    if desync_template:
        suf += f"_t{desync_template[:8]}"
    # 包含密度信息
    if density_uavs_per_km2 > 0:
        suf += f"_rho{int(density_uavs_per_km2)}"
    # GM3D 应力档位（非 nominal 时必须进 key，避免场景缓存串味）
    if mode == "gauss_markov_3d":
        gms = (gm3d_stress or "nominal").strip().lower()
        if gms not in GM3D_STRESS_PRESETS:
            gms = "nominal"
        if gms != "nominal":
            suf += f"_gms{gms[:3]}"
    if channel_bank_suffix:
        suf += channel_bank_suffix
    return f"{mode}_n{size}_s{seed}{suf}"


def _load_or_build_scenario_bank(
    bank_path: Path,
    sizes: List[int],
    modes: List[str],
    args: argparse.Namespace,
) -> Dict[str, Dict[str, Any]]:
    bank: Dict[str, Dict[str, Any]] = {}
    if bank_path.exists():
        try:
            data = json.loads(bank_path.read_text(encoding="utf-8"))
            loaded = data.get("scenarios", {})
            if isinstance(loaded, dict):
                bank = loaded
        except (OSError, json.JSONDecodeError):
            bank = {}

    changed = False
    for mode in modes:
        for size in sizes:
            key = _scenario_bank_key(
                mode,
                size,
                args.seed,
                getattr(args, "desync_multi_round", False),
                getattr(args, "desync_boundary_recovery", False),
                getattr(args, "desync_template", ""),
                getattr(args, "density_uavs_per_km2", 0.0),
                getattr(args, "gm3d_stress", "nominal"),
                _channel_bank_suffix(args),
                reauth_rounds=int(getattr(args, "reauth_rounds", 3) or 3),
                reauth_spacing_s=float(getattr(args, "reauth_spacing_s", 24.0) or 24.0),
                desync_attack_min_completed_sessions=getattr(
                    args, "desync_attack_min_completed_sessions", None
                ),
                desync_attack_max_completed_sessions=getattr(
                    args, "desync_attack_max_completed_sessions", None
                ),
            )
            if key in bank:
                continue
            # 场景先冻结一次（protocol 先占位，后续每个协议仅覆写 protocol 字段）
            frozen_cfg = build_unified_config(
                size,
                "PMAP",
                mode,
                seed=args.seed,
                uplink_loss_rate=args.uplink_loss_rate,
                downlink_loss_rate=args.downlink_loss_rate,
                d2z_ack_timeout_s=args.d2z_ack_timeout_s,
                max_d2z_attempts=args.max_d2z_attempts,
                desync_template=args.desync_template,
                desync_multi_round=getattr(args, "desync_multi_round", False),
                desync_boundary_recovery=getattr(args, "desync_boundary_recovery", False),
                retry_d2z_after_intercept_s=args.retry_d2z_after_intercept_s,
                rssi_loss_enabled=args.rssi_loss_enabled,
                rssi_good_dbm=args.rssi_good_dbm,
                rssi_bad_dbm=args.rssi_bad_dbm,
                rssi_loss_good=args.rssi_loss_good,
                rssi_loss_bad=args.rssi_loss_bad,
                academic_profile=args.academic_profile,
                burst_loss_enabled=args.burst_loss_enabled,
                burst_p_good_to_bad=args.burst_p_good_to_bad,
                burst_p_bad_to_good=args.burst_p_bad_to_good,
                burst_loss_good=args.burst_loss_good,
                burst_loss_bad=args.burst_loss_bad,
                density_uavs_per_km2=getattr(args, "density_uavs_per_km2", 0.0),
                gm3d_stress=getattr(args, "gm3d_stress", "nominal"),
                reauth_rounds=int(getattr(args, "reauth_rounds", 3) or 3),
                reauth_spacing_s=float(getattr(args, "reauth_spacing_s", 24.0) or 24.0),
                desync_attack_min_completed_sessions=getattr(
                    args, "desync_attack_min_completed_sessions", None
                ),
                desync_attack_max_completed_sessions=getattr(
                    args, "desync_attack_max_completed_sessions", None
                ),
            )
            frozen_cfg.setdefault("scenario", {})["frozen_scenario_key"] = key
            bank[key] = frozen_cfg
            changed = True

    if changed or (not bank_path.exists()):
        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "seed": args.seed,
            "scenarios": bank,
        }
        bank_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return bank


def _config_from_frozen_scenario(base_cfg: Dict[str, Any], protocol: str, size: int, mode: str, seed: int) -> Dict[str, Any]:
    cfg = copy.deepcopy(base_cfg)
    cfg["protocol"] = protocol
    cfg["task_id"] = f"unified_{mode}_n{size}_{protocol.lower()}_s{seed}"
    cfg["name"] = f"Unified swarm ({mode}) N={size} {protocol}"
    cfg["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    cfg.setdefault("scenario", {})["protocol_eval"] = protocol
    return cfg


def run_one(cfg_path: str, log_dir: Path, sim_id: int, ns3_bin: str, sim_script: str) -> tuple[int, str, str]:
    _prepare_log_dir(log_dir)
    env = os.environ.copy()
    env["CONFIG_FILE"] = str(Path(cfg_path).resolve())
    env["SIM_LOG_DIR"] = str(log_dir.resolve())
    env["SIM_ID"] = str(sim_id)
    env.setdefault("MALLOC_ARENA_MAX", "2")
    p = subprocess.run(
        [ns3_bin, "run", sim_script],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    return p.returncode, (p.stdout or "")[-6000:], (p.stderr or "")[-6000:]


def main() -> int:
    ap = argparse.ArgumentParser(description="Unified swarm scenario experiment")
    ap.add_argument("--sizes", default="10,30", help="comma sizes, e.g. 10,30,50")
    ap.add_argument("--protocols", default="PMAP,PMAP_ACK,RLBA_UAV")
    ap.add_argument("--motion-modes", default="trace_dataset,task_random")
    ap.add_argument("--seeds", type=str, default="20260417", help="comma-separated seeds for multi-run, e.g. 20260417,20260418,20260419")
    ap.add_argument("--uplink-loss-rate", type=float, default=0.0)
    ap.add_argument("--downlink-loss-rate", type=float, default=0.0)
    ap.add_argument("--d2z-ack-timeout-s", type=float, default=1.5, help="ACK超时(秒)，默认1.5s。正常认证<1s完成，1.5s足够覆盖网络延迟")
    ap.add_argument("--max-d2z-attempts", type=int, default=2)
    ap.add_argument("--desync-template", default="")
    ap.add_argument(
        "--desync-multi-round",
        action="store_true",
        help="激进多轮：每 UAV 3 次认证 + allow_reauth，且攻击每轮生效（desync_attack_every_round）",
    )
    ap.add_argument(
        "--desync-boundary-recovery",
        action="store_true",
        help="边界自恢复：多轮认证 + allow_reauth，但攻击仍受 first_auth_only 限制；需配合 boundary_* 模板",
    )
    ap.add_argument(
        "--desync-boundary-profile",
        choices=["m3m4_once", "ack_once"],
        default="ack_once",
        help="与 --desync-boundary-recovery 联用：选择 boundary_m3m4_once 或 boundary_ack_once",
    )
    ap.add_argument(
        "--reauth-rounds",
        type=int,
        default=3,
        help="多轮/边界自恢复模式下每 UAV 的鉴权调度次数（time_offsets_s 长度），默认 3",
    )
    ap.add_argument(
        "--reauth-spacing-s",
        type=float,
        default=24.0,
        help="相邻两次鉴权触发的时间间隔（秒），默认 24",
    )
    ap.add_argument(
        "--desync-attack-min-completed-sessions",
        type=int,
        default=None,
        help="去同步拦截前要求该 UAV 已完成的 D2Z 成功次数；省略时边界自恢复按约半数轮次后首次拦截",
    )
    ap.add_argument(
        "--desync-attack-max-completed-sessions",
        type=int,
        default=None,
        help="攻击窗口上限：完成次数超过此值后停止攻击。用于持续多轮攻击+恢复场景",
    )
    ap.add_argument("--retry-d2z-after-intercept-s", type=float, default=2.0)
    ap.add_argument("--rssi-loss-enabled", action="store_true")
    ap.add_argument("--rssi-good-dbm", type=float, default=-65.0)
    ap.add_argument("--rssi-bad-dbm", type=float, default=-90.0)
    ap.add_argument("--rssi-loss-good", type=float, default=0.0)
    ap.add_argument("--rssi-loss-bad", type=float, default=0.5)
    ap.add_argument("--burst-loss-enabled", action="store_true")
    ap.add_argument("--burst-p-good-to-bad", type=float, default=0.02)
    ap.add_argument("--burst-p-bad-to-good", type=float, default=0.25)
    ap.add_argument("--burst-loss-good", type=float, default=0.01)
    ap.add_argument("--burst-loss-bad", type=float, default=0.75)
    ap.add_argument(
        "--academic-profile",
        default="infocom11_open_field",
        help="academic-aligned channel profile: infocom11_open_field|infocom11_campus|vtc_a2g_shadowing",
    )
    ap.add_argument(
        "--communication-mode",
        choices=["u2i", "u2u"],
        default="u2i",
        help="通信模式: u2i=UAV-ZSP-UAV (默认), u2u=UAV间直接认证 (D2D)",
    )
    ap.add_argument("--out-root", type=Path, default=ROOT / "experiments" / "results_unified_swarm")
    ap.add_argument(
        "--density-uavs-per-km2",
        type=float,
        default=0.0,
        help="网络密度：每平方公里UAV数量。>0时启用密度模型计算仿真区域，并自动部署多ZSP",
    )
    ap.add_argument(
        "--densities",
        default="",
        help="密度级别列表，用于scalability实验: 'low,medium,high' 对应 1,10,50 UAVs/km²",
    )
    ap.add_argument(
        "--gm3d-stress",
        choices=["conservative", "nominal", "aggressive"],
        default="nominal",
        help="Gauss-Markov 3D 机动应力档位：只调 α/速度统计量；信道丢包仍由 academic_profile 与 RSSI/burst 开关决定",
    )
    ap.add_argument(
        "--scenario-bank-path",
        type=Path,
        default=None,
        help="optional frozen scenario bank json path; default: <out-root>/scenario_bank.json",
    )
    ap.add_argument("--between-sleep", type=float, default=10.0)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--ns3", default=DEFAULT_NS3)
    ap.add_argument("--simulator", default=DEFAULT_SIM)
    args = ap.parse_args()

    if getattr(args, "desync_boundary_recovery", False):
        cur = str(getattr(args, "desync_template", "") or "").strip()
        if not cur.startswith("boundary_"):
            prof = getattr(args, "desync_boundary_profile", None) or "ack_once"
            tpl_map = {"m3m4_once": "boundary_m3m4_once", "ack_once": "boundary_ack_once"}
            args.desync_template = tpl_map.get(prof, "boundary_ack_once")

    sizes = [int(x.strip()) for x in args.sizes.split(",") if x.strip()]
    protocols = [x.strip().upper() for x in args.protocols.split(",") if x.strip()]
    modes = [x.strip() for x in args.motion_modes.split(",") if x.strip()]
    seeds = [int(x.strip()) for x in args.seeds.split(",") if x.strip()]

    # 解析密度级别
    density_map = {"low": 1.0, "medium": 10.0, "high": 50.0}
    densities: List[float] = []
    if args.densities:
        densities = [density_map.get(d.strip().lower(), 0.0) for d in args.densities.split(",") if d.strip()]
    if args.density_uavs_per_km2 > 0:
        densities.append(args.density_uavs_per_km2)
    if not densities:
        densities = [0.0]  # 默认不使用密度模型

    out_root = args.out_root
    out_root.mkdir(parents=True, exist_ok=True)

    # 为每个种子和密度构建独立的 scenario bank
    seed_banks: Dict[tuple, Dict[str, Any]] = {}
    for seed in seeds:
        for density in densities:
            args.seed = seed
            args.density_uavs_per_km2 = density
            density_suffix = f"_d{int(density)}" if density > 0 else ""
            bank_path = args.scenario_bank_path or (out_root / f"scenario_bank_s{seed}{density_suffix}.json")
            seed_banks[(seed, density)] = _load_or_build_scenario_bank(bank_path, sizes, modes, args)

    runs: List[Dict[str, Any]] = []
    base_id = int(time.time()) % 900_000_000

    for mode in modes:
        for size in sizes:
            for proto in protocols:
                for seed in seeds:
                    for density in densities:
                        density_tag = f"_d{int(density)}" if density > 0 else ""
                        gm_tag = ""
                        if mode == "gauss_markov_3d" and getattr(args, "gm3d_stress", "nominal") != "nominal":
                            gm_tag = f"_gm{args.gm3d_stress}"
                        ch_tag = _channel_bank_suffix(args)
                        tag = f"{mode}_n{size}{density_tag}_{proto.lower()}_s{seed}{gm_tag}{ch_tag}"
                        run_dir = out_root / tag
                        result_path = run_dir / "result.json"
                        if args.resume and result_path.exists():
                            try:
                                cached = json.loads(result_path.read_text(encoding="utf-8"))
                                if cached.get("status") == "ok":
                                    print(f"[resume] skip {tag}", flush=True)
                                    runs.append(cached)
                                    _write_manifest(out_root, runs)
                                    continue
                            except (OSError, json.JSONDecodeError):
                                pass

                        scenario_bank = seed_banks[(seed, density)]
                        frozen_key = _scenario_bank_key(
                            mode,
                            size,
                            seed,
                            getattr(args, "desync_multi_round", False),
                            getattr(args, "desync_boundary_recovery", False),
                            getattr(args, "desync_template", ""),
                            density,
                            getattr(args, "gm3d_stress", "nominal"),
                            _channel_bank_suffix(args),
                            reauth_rounds=int(getattr(args, "reauth_rounds", 3) or 3),
                            reauth_spacing_s=float(getattr(args, "reauth_spacing_s", 24.0) or 24.0),
                            desync_attack_min_completed_sessions=getattr(
                                args, "desync_attack_min_completed_sessions", None
                            ),
                            desync_attack_max_completed_sessions=getattr(
                                args, "desync_attack_max_completed_sessions", None
                            ),
                        )
                        frozen_cfg = scenario_bank[frozen_key]
                        cfg = _config_from_frozen_scenario(frozen_cfg, proto, size, mode, seed)
                        # 确保配置中包含密度和区域信息
                        cfg.setdefault("scenario", {})["density_uavs_per_km2"] = density
                        (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
                        cfg_path = run_dir / "inputs" / "config.json"
                        with open(cfg_path, "w", encoding="utf-8") as f:
                            json.dump(cfg, f, indent=2)

                        sim_id = base_id + size * 31 + abs(hash((proto, mode, seed, density))) % 10000
                        print(f"[run] start {tag} sim_id={sim_id} density={density}", flush=True)
                        t0 = time.time()
                        code, out_tail, err_tail = run_one(
                            str(cfg_path), run_dir / "logs", sim_id, args.ns3, args.simulator
                        )
                        elapsed = round(time.time() - t0, 2)
                        print(f"[run] done {tag} code={code} elapsed={elapsed}s", flush=True)

                        rec: Dict[str, Any] = {
                            "tag": tag,
                            "motion_mode": mode,
                            "size": size,
                            "density": density,
                            "protocol": proto,
                            "seed": seed,
                            "academic_profile": args.academic_profile,
                            "config_path": str(cfg_path),
                            "log_dir": str(run_dir / "logs"),
                            "ns3_exit_code": code,
                            "elapsed_s": elapsed,
                            "status": "ok" if code == 0 else "failed",
                        }
                        if code == 0:
                            rec["analysis"] = _analyze_log_dir(str(run_dir / "logs"))
                            per = rec["analysis"].get("per_uav") or {}
                            rec["uavs_with_ge_one_success"] = sum(
                                1 for _, v in per.items() if v.get("successful", 0) >= 1
                            )
                        else:
                            blob = (out_tail or "") + (err_tail or "")
                            rec["failure_hint"] = (
                                "likely_oom_cling_jit"
                                if "allocate memory" in blob.lower()
                                else "unknown"
                            )
                            rec["stderr_tail"] = err_tail[-2000:]
                        with open(result_path, "w", encoding="utf-8") as f:
                            json.dump(rec, f, indent=2, default=str)
                        runs.append(rec)
                        _write_manifest(out_root, runs)
                        if args.between_sleep > 0:
                            time.sleep(float(args.between_sleep))
                        gc.collect()

    print(json.dumps({"manifest": str(out_root / "swarm_manifest.json"), "runs": len(runs)}, indent=2))
    return 0 if all(r.get("status") == "ok" for r in runs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
