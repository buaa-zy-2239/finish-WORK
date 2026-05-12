"""
机动应力测试参数矩阵定义
对应前端 scenarioGenerator.js 中 mobility_stress_test 的参数体系
"""

import math
from typing import Dict, List

# ──────────────────────────────────────────────
# 1. 参数维度定义（对应 constants/index.js）
# ──────────────────────────────────────────────

SWARM_SIZES = [10, 30, 50, 100]
REDUCED_SWARM_SIZES = [10, 30, 50]

DENSITY_OPTIONS = [
    {"value": 1, "label": "low (1 UAV/km²)"},
    {"value": 10, "label": "medium (10 UAV/km²)"},
    {"value": 50, "label": "high (50 UAV/km²)"},
]
REDUCED_DENSITY_OPTIONS = [
    {"value": 1, "label": "low (1 UAV/km²)"},
    {"value": 10, "label": "medium (10 UAV/km²)"},
]

GM3D_STRESS_OPTIONS = [
    {"value": "hover", "label": "悬停 (1±0.5 m/s)"},
    {"value": "conservative", "label": "保守 (3±2 m/s)"},
    {"value": "nominal", "label": "标准 (5±3 m/s)"},
    {"value": "aggressive", "label": "激进 (15±7 m/s)"},
    {"value": "high_speed", "label": "高速 (18±8 m/s)"},
]
REDUCED_GM3D_STRESS_OPTIONS = [
    {"value": "hover", "label": "悬停 (1±0.5 m/s)"},
    {"value": "nominal", "label": "标准 (5±3 m/s)"},
    {"value": "high_speed", "label": "高速 (18±8 m/s)"},
]

G3PP_SCENARIO_OPTIONS = [
    {"value": "uma", "label": "UMA (Urban Macro 城市宏站)"},
    {"value": "umi", "label": "UMI (Urban Micro Street Canyon 城市微站)"},
    {"value": "rma", "label": "RMA (Rural Macro 农村宏站)"},
]

CARRIER_FREQUENCY_OPTIONS = [
    {"value": 2.4e9, "label": "2.4 GHz"},
    {"value": 5.0e9, "label": "5.0 GHz"},
    {"value": 5.9e9, "label": "5.9 GHz (C-V2X 常用)"},
    {"value": 6.0e9, "label": "6.0 GHz"},
]
REDUCED_CARRIER_FREQUENCY_OPTIONS = [
    {"value": 2.4e9, "label": "2.4 GHz"},
    {"value": 5.9e9, "label": "5.9 GHz (C-V2X 常用)"},
]

# ──────────────────────────────────────────────
# 2. GM3D 各档位速度参数（对应 scenarioGenerator.js stressParams）
# ──────────────────────────────────────────────

GM3D_STRESS_PARAMS = {
    "hover": {
        "alpha": 0.98,
        "mean_speed_mps": 1.0,
        "speed_std_mps": 0.5,
        "altitude_std_m": 8.0,
    },
    "conservative": {
        "alpha": 0.9,
        "mean_speed_mps": 3.0,
        "speed_std_mps": 2.0,
        "altitude_std_m": 12.0,
    },
    "nominal": {
        "alpha": 0.8,
        "mean_speed_mps": 5.0,
        "speed_std_mps": 4.0,
        "altitude_std_m": 18.0,
    },
    "aggressive": {
        "alpha": 0.6,
        "mean_speed_mps": 15.0,
        "speed_std_mps": 7.0,
        "altitude_std_m": 25.0,
    },
    "high_speed": {
        "alpha": 0.4,
        "mean_speed_mps": 18.0,
        "speed_std_mps": 8.0,
        "altitude_std_m": 30.0,
    },
}

# ──────────────────────────────────────────────
# 3. 3GPP 环境预设参数（对应 constants/index.js THREE_GPP_ENVIRONMENT_PRESETS）
# ──────────────────────────────────────────────

THREE_GPP_PRESETS = {
    "uma": {
        "name": "Urban Macro",
        "pathloss_exponent": 3.67,
        "los_probability_params": {"h_bs": 35, "h_ut": 1.5},
        "cell_radius": 1000,
        "recommended_uav_altitude": 80,
        "shadowing_std_db": 8.0,
    },
    "umi": {
        "name": "Urban Micro",
        "pathloss_exponent": 4.03,
        "los_probability_params": {"h_bs": 10, "h_ut": 1.5},
        "cell_radius": 500,
        "recommended_uav_altitude": 40,
        "shadowing_std_db": 6.0,
    },
    "rma": {
        "name": "Rural Macro",
        "pathloss_exponent": 3.03,
        "los_probability_params": {"h_bs": 45, "h_ut": 1.5},
        "cell_radius": 2000,
        "recommended_uav_altitude": 100,
        "shadowing_std_db": 4.0,
    },
}

# 3GPP 场景 → 通信范围映射
G3PP_COMM_RANGE = {
    "uma": 1000,
    "umi": 500,
    "rma": 2000,
}

# ──────────────────────────────────────────────
# 4. 工具函数
# ──────────────────────────────────────────────

def calc_area_size(swarm_size: int, density: int) -> float:
    """根据蜂群规模设定固定区域大小（单位：米）
    密度只影响UAV数量，不影响区域大小
    """
    if swarm_size >= 50:
        return 1500
    elif swarm_size >= 30:
        return 1000
    else:
        return 500


def build_zsp_grid(swarm_size: int, density: int, scenario: str):
    """根据区域大小和场景生成 ZSP 网格
    返回 ZSP 配置列表 [{"id": int, "position": [x, y, z]}]
    现实环境：ZSP应密集部署以提供无缝覆盖
    策略：蜂群规模越大，ZSP网格越密（按比例），但限制最大数量
    """
    side_m = calc_area_size(swarm_size, density)
    cell_radius = G3PP_COMM_RANGE.get(scenario, 1000)

    zsp_spacing = cell_radius * 0.9

    if scenario == "umi":
        cols = 5
        rows = 5
    elif scenario == "uma":
        cols = 2
        rows = 2
    else:
        cols = 2
        rows = 2

    zsps = []
    zsp_id = 1
    uav_alt = THREE_GPP_PRESETS[scenario]["recommended_uav_altitude"]
    zsp_alt = 30 if scenario == "umi" else 50

    for r in range(rows):
        for c in range(cols):
            x = -side_m / 2 + (c + 0.5) * (side_m / cols)
            y = -side_m / 2 + (r + 0.5) * (side_m / rows)
            zsps.append({
                "id": zsp_id,
                "position": [round(x, 1), round(y, 1), zsp_alt],
                "compute_profile": {
                    "uav_altitude_m": uav_alt,
                    "carrier_freq_hz": 2.4e9,
                }
            })
            zsp_id += 1

    return zsps


def build_uav_positions(swarm_size: int, density: int, scenario: str):
    """生成 UAV 初始位置
    基于密度计算区域大小，在区域内随机/均匀分布
    """
    side_m = calc_area_size(swarm_size, density)
    uav_alt = THREE_GPP_PRESETS[scenario]["recommended_uav_altitude"]

    cols = int(math.ceil(math.sqrt(swarm_size)))
    rows = int(math.ceil(swarm_size / cols))

    positions = []
    for i in range(swarm_size):
        r = i // cols
        c = i % cols
        x = -side_m / 2 + (c + 0.5) * (side_m / cols)
        y = -side_m / 2 + (r + 0.5) * (side_m / rows)
        alt = uav_alt + (hash(f"uav_{i}") % 21 - 10)
        positions.append([round(x, 1), round(y, 1), round(alt, 1)])

    return positions


def build_mobility_config(stress_level: str):
    """构建 Gauss-Markov 3D 移动模型配置"""
    params = GM3D_STRESS_PARAMS[stress_level]
    return {
        "type": "gauss_markov_3d",
        "alpha": params["alpha"],
        "mean_speed_mps": params["mean_speed_mps"],
        "speed_std_mps": params["speed_std_mps"],
        "altitude_std_m": params["altitude_std_m"],
        "TimeStep": 0.1,
    }


def build_channel_config(scenario: str, carrier_freq_hz: float):
    """构建信道配置"""
    return {
        "type": "CSMA",
        "datarate": "100Mbps",
        "loss_model": "3gpp_native",
        "scenario_type": scenario,
        "carrier_freq_hz": carrier_freq_hz,
        "enable_shadowing": True,
    }


def build_experiment_config(
    swarm_size: int,
    density: int,
    stress_level: str,
    scenario: str,
    carrier_freq_hz: float,
    duration: int = 60,
) -> dict:
    duration = 30
    """构建完整的实验配置字典"""
    uav_positions = build_uav_positions(swarm_size, density, scenario)
    zsps = build_zsp_grid(swarm_size, density, scenario)
    comm_range = G3PP_COMM_RANGE.get(scenario, 1000)

    mobility_config = build_mobility_config(stress_level)
    channel_config = build_channel_config(scenario, carrier_freq_hz)

    exp_id = (
        f"s{swarm_size}_d{density}_"
        f"{stress_level}_"
        f"{scenario}_"
        f"{carrier_freq_hz/1e9:.1f}ghz"
    )

    time_offsets = [5, 15]

    uavs = []
    for i in range(swarm_size):
        uavs.append({
            "id": i,
            "mobility": {
                **mobility_config,
                "area_size_x": calc_area_size(swarm_size, density),
                "area_size_y": calc_area_size(swarm_size, density),
            },
            "auth_trigger": {
                "initial_on_connect": True,
                "allow_reauth": True,
                "on_handover": True,
                "handover_delay_s": 0.5,
                "time_offsets_s": time_offsets,
            },
            "link_state": {
                "comm_range_m": comm_range,
                "zsp_handover": {
                    "enabled": True,
                    "rssi_threshold_dbm": -95,
                    "hysteresis_db": 5,
                    "min_dwell_time_s": 1.0,
                    "handover_delay_s": 0.3,
                    "reauth_after_handover": True,
                },
            },
        })

    config = {
        "id": f"mobility_stress_{exp_id}",
        "name": (
            f"蜂群{swarm_size} 密度{density}/km² "
            f"速度{stress_level} 场景{scenario.upper()} "
            f"频率{int(carrier_freq_hz/1e9)}GHz"
        ),
        "duration": duration,
        "uavs": uavs,
        "zsps": zsps,
        "channel": channel_config,
        "security_profile": {
            "adversary": "none",
            "attack_model": {
                "d2z_ack_timeout_s": 0.5,
                "max_d2z_attempts": 1,
                "d2z_retry_delay_s": 0.1,
            },
        },
        "protocol": "PMAP_ACK",
        "enable_blockchain": True,
    }

    return config


def get_all_combinations(mode: str = "reduced") -> List[Dict]:
    """枚举所有参数组合

    Args:
        mode: "reduced"（默认, 108组）或 "full"（720组）
    """
    if mode == "full":
        swarm_sizes = SWARM_SIZES
        density_opts = DENSITY_OPTIONS
        stress_opts = GM3D_STRESS_OPTIONS
    else:
        swarm_sizes = REDUCED_SWARM_SIZES
        density_opts = REDUCED_DENSITY_OPTIONS
        stress_opts = REDUCED_GM3D_STRESS_OPTIONS

    scenario_opts = G3PP_SCENARIO_OPTIONS
    freq_opts = REDUCED_CARRIER_FREQUENCY_OPTIONS if mode == "reduced" else CARRIER_FREQUENCY_OPTIONS

    combinations = []
    idx = 0
    for swarm_size in swarm_sizes:
        for density_opt in density_opts:
            density = density_opt["value"]
            for stress_opt in stress_opts:
                stress = stress_opt["value"]
                for scenario_opt in scenario_opts:
                    scenario = scenario_opt["value"]
                    for freq_opt in freq_opts:
                        freq = freq_opt["value"]
                        combinations.append({
                            "index": idx,
                            "swarm_size": swarm_size,
                            "density": density,
                            "stress_level": stress,
                            "scenario": scenario,
                            "carrier_freq_hz": freq,
                            "config": build_experiment_config(
                                swarm_size, density, stress, scenario, freq
                            ),
                        })
                        idx += 1
    return combinations


def format_combination_id(combo: dict) -> str:
    """生成组合的唯一标识符"""
    s = combo["swarm_size"]
    d = combo["density"]
    g = combo["stress_level"]
    sc = combo["scenario"]
    f = combo["carrier_freq_hz"] / 1e9
    return f"s{s}_d{d}_{g}_{sc}_{f:.1f}ghz"
