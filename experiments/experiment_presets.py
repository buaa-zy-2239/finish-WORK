"""
论文向实验：预设 → `swarm_unified_scenario_experiment.py` 命令行参数。

用法见 `run_paper_experiment.py` 与 **`experiments/EXPERIMENTS.md` 第 0 节（复制即用复现）**。此处只描述「可复现矩阵」，不包含 NS3 可执行路径。
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
SWARM = ROOT / "experiments" / "swarm_unified_scenario_experiment.py"


@dataclass
class SwarmMatrix:
    """单次 swarm 调用的矩阵默认值（均可被 CLI 覆盖）。"""

    desync_template: str = ""
    desync_multi_round: bool = False
    desync_boundary_recovery: bool = False
    desync_boundary_profile: str = "ack_once"
    reauth_rounds: int = 3
    reauth_spacing_s: float = 24.0
    desync_attack_min_completed_sessions: Optional[int] = None
    desync_attack_max_completed_sessions: Optional[int] = None
    uplink_loss_rate: float = 0.0
    downlink_loss_rate: float = 0.0
    default_sizes: str = "10,30"
    default_protocols: str = "PMAP,PMAP_ACK"
    # 顶会标准：30个独立种子，确保95%置信区间精度
    default_seeds: str = "20260417,20260418,20260419,20260420,20260421,20260422,20260423,20260424,20260425,20260426,20260427,20260428,20260429,20260430,20260501,20260502,20260503,20260504,20260505,20260506,20260507,20260508,20260509,20260510,20260511,20260512,20260513,20260514,20260515,20260516"
    default_motion_modes: str = "gauss_markov_3d"  # 顶会标准：3D移动模型
    default_academic_profile: str = "twc2025_elevation_aware"  # 顶会标准：TWC 2025信道
    default_between_sleep: float = 2.0
    default_out_root: str = "experiments/results_unified_swarm"
    # 顶会标准：启用统计汇总
    enable_statistical_summary: bool = True
    min_runs_for_statistical_analysis: int = 30


@dataclass
class ExperimentKind:
    """实验类型：人类可读说明 + 默认 swarm 矩阵。"""

    title: str
    swarm: SwarmMatrix = field(default_factory=SwarmMatrix)
    notes: str = ""


KINDS: Dict[str, ExperimentKind] = {
    "baseline": ExperimentKind(
        title="无去同步、无额外丢包（信道对照）",
        swarm=SwarmMatrix(
            default_out_root="experiments/results_paper_baseline",
        ),
    ),
    "desync_attack": ExperimentKind(
        title="组合去同步（上行 M3/M4 丢弃 + 下行 ACK 抑制），单轮默认",
        swarm=SwarmMatrix(
            desync_template="uplink_rotation_drop,downlink_d2z_ack_drop",
            default_out_root="experiments/results_paper_desync_attack",
        ),
    ),
    "desync_multiround": ExperimentKind(
        title="激进多轮：每机多轮鉴权且每轮可受攻击",
        swarm=SwarmMatrix(
            desync_template="uplink_rotation_drop,downlink_d2z_ack_drop",
            desync_multi_round=True,
            default_out_root="experiments/results_paper_desync_multiround",
        ),
    ),
    "desync_boundary": ExperimentKind(
        title="边界去同步 + 多轮自恢复（需 --boundary-profile ack_once|m3m4_once）",
        swarm=SwarmMatrix(
            desync_boundary_recovery=True,
            desync_boundary_profile="ack_once",
            default_out_root="experiments/results_paper_desync_boundary",
        ),
        notes="模板由 swarm 根据 profile 自动设为 boundary_*；与 experiments/EXPERIMENTS.md 第 4 节一致。",
    ),
    "desync_boundary_micro": ExperimentKind(
        title="微观叙事：单机–ZSP、多轮认证、中途边界去同步（N=1，task_random）",
        swarm=SwarmMatrix(
            desync_boundary_recovery=True,
            desync_boundary_profile="ack_once",
            default_sizes="1",
            default_protocols="PMAP,PMAP_ACK",
            default_motion_modes="task_random",
            default_seeds="20260417,20260418,20260419",
            default_out_root="experiments/results_desync_microscopic",
            default_between_sleep=2.0,
            reauth_rounds=120,
            reauth_spacing_s=3.0,
            desync_attack_min_completed_sessions=10,
        ),
        notes="单机单次仿真内多轮 D2Z 调度（默认 120 次触发、3s 间隔，可改 SwarmMatrix.reauth_*）；≥20 轮时默认约半数成功后再首次边界拦截。间隔缩短可缓解 PMAP_ACK dual-PID 窗口过期问题。",
    ),
    "desync_ack_sustained": ExperimentKind(
        title="持续ACK攻击+恢复：连续10轮拦截后停止，验证PMAP_ACK恢复能力",
        swarm=SwarmMatrix(
            desync_boundary_recovery=True,
            desync_boundary_profile="ack_once",
            default_sizes="1",
            default_protocols="PMAP_ACK",  # 仅PMAP_ACK
            default_motion_modes="task_random",
            default_seeds="20260417,20260418,20260419",
            default_out_root="experiments/results_desync_microscopic/ack_sustained",
            default_between_sleep=2.0,
            reauth_rounds=120,
            reauth_spacing_s=3.0,
            desync_attack_min_completed_sessions=10,  # 第10轮开始攻击
            desync_attack_max_completed_sessions=20,  # 第20轮停止攻击（持续10轮攻击窗口）
        ),
        notes="与ack_once对应：ack_once验证单轮ACK攻击恢复，ack_sustained验证连续10轮ACK攻击后的恢复能力。两者共同证明PMAP_ACK对ACK攻击的鲁棒性。",
    ),
    "desync_m3m4_sustained": ExperimentKind(
        title="持续M3/M4拦截+恢复：连续10轮上行丢弃后停止，验证PMAP与PMAP_ACK恢复能力",
        swarm=SwarmMatrix(
            desync_boundary_recovery=True,
            desync_boundary_profile="m3m4_once",
            default_sizes="1",
            default_protocols="PMAP,PMAP_ACK",
            default_motion_modes="task_random",
            default_seeds="20260417,20260418,20260419",
            default_out_root="experiments/results_desync_microscopic/m3m4_sustained",
            default_between_sleep=2.0,
            reauth_rounds=120,
            reauth_spacing_s=3.0,
            desync_attack_min_completed_sessions=10,
            desync_attack_max_completed_sessions=20,
        ),
        notes="与 m3m4_once 对称：m3m4_once 为单轮边界 M3/M4 丢弃；本 kind 为与 ack_sustained 相同的 10 轮攻击窗口，验证持续上行拦截后的恢复。",
    ),
    "desync_single_round": ExperimentKind(
        title="单轮M3/M4边界去同步（PMAP和PMAP_ACK公平对比）",
        swarm=SwarmMatrix(
            desync_boundary_recovery=False,
            desync_template="boundary_m3m4_once",  # M3/M4攻击，两种协议都受影响
            default_out_root="experiments/results_paper_desync_single_round",
        ),
        notes="M3/M4边界攻击: 丢弃上行M3/M4消息。PMAP和PMAP_ACK都需验证去同步恢复能力。单轮认证排除调度混淆。",
    ),
    "desync_ack_single_round": ExperimentKind(
        title="单轮ACK边界攻击（仅PMAP_ACK受影响）",
        swarm=SwarmMatrix(
            desync_boundary_recovery=False,
            desync_template="boundary_ack_once",  # ACK攻击，仅影响PMAP_ACK
            default_out_root="experiments/results_paper_desync_ack_single_round",
        ),
        notes="ACK边界攻击: 抑制D2Z_ACK发送。PMAP不受影响(100%)，PMAP_ACK需验证恢复能力。",
    ),
    "top_tier": ExperimentKind(
        title="顶会取向双臂流水线（ack_once + m3m4_once + 轮次分析 + 图）",
        swarm=SwarmMatrix(),
        notes="不直接映射单次 swarm；由 run_top_tier_desync_experiment.py 顺序执行。",
    ),
    "scalability": ExperimentKind(
        title="网络规模与密度测试（Scalability & Density Simulation）",
        swarm=SwarmMatrix(
            desync_template="",  # 无攻击，纯scalability测试
            default_sizes="10,30,50",
            default_protocols="PMAP,PMAP_ACK",
            default_motion_modes="gauss_markov_3d",  # 使用GM3D移动模型
            default_out_root="experiments/results_paper_scalability",
            default_between_sleep=2.0,
        ),
        notes="网络规模N=10/30/50/100，密度ρ=1/10/50 UAVs/km²，Gauss-Markov 3D移动模型，IEEE 802.11ah信道。",
    ),
}


def list_kind_titles() -> Dict[str, str]:
    return {k: v.title for k, v in KINDS.items()}


def default_ns3_bin() -> str:
    return os.environ.get("NS3_BIN", "/home/zhang/ns/ns-allinone-3.43/ns-3.43/ns3")


def default_simulator() -> str:
    return os.environ.get("SIMULATOR", str(ROOT / "simulator_builder.py"))


def build_swarm_argv(
    *,
    kind: str,
    sizes: str,
    protocols: str,
    seeds: str,
    motion_modes: str,
    out_root: Path,
    academic_profile: str,
    ns3_bin: str,
    simulator: str,
    between_sleep: Optional[float] = None,
    boundary_profile: Optional[str] = None,
    loss_pct: Optional[float] = None,
    densities: Optional[str] = None,
) -> List[str]:
    if kind not in KINDS:
        raise KeyError(f"unknown kind {kind!r}; known: {', '.join(sorted(KINDS))}")
    spec = KINDS[kind]
    sm = spec.swarm
    upl = sm.uplink_loss_rate
    down = sm.downlink_loss_rate
    if loss_pct is not None:
        upl = down = float(loss_pct)

    cmd: List[str] = [
        sys.executable,
        str(SWARM),
        "--sizes",
        sizes,
        "--protocols",
        protocols,
        "--motion-modes",
        motion_modes,
        "--seeds",
        seeds,
        "--uplink-loss-rate",
        str(upl),
        "--downlink-loss-rate",
        str(down),
        "--out-root",
        str(out_root),
        "--between-sleep",
        str(between_sleep if between_sleep is not None else sm.default_between_sleep),
        "--academic-profile",
        academic_profile or sm.default_academic_profile,
        "--ns3",
        ns3_bin,
        "--simulator",
        simulator,
    ]
    if (sm.desync_template or "").strip():
        cmd += ["--desync-template", sm.desync_template.strip()]
    if sm.desync_multi_round:
        cmd.append("--desync-multi-round")
    if sm.desync_boundary_recovery:
        cmd.append("--desync-boundary-recovery")
        prof = (boundary_profile or sm.desync_boundary_profile or "ack_once").strip()
        cmd += ["--desync-boundary-profile", prof]
    if densities:
        cmd += ["--densities", densities]
    cmd += ["--reauth-rounds", str(int(sm.reauth_rounds))]
    cmd += ["--reauth-spacing-s", str(float(sm.reauth_spacing_s))]
    if sm.desync_attack_min_completed_sessions is not None:
        cmd += [
            "--desync-attack-min-completed-sessions",
            str(int(sm.desync_attack_min_completed_sessions)),
        ]
    if sm.desync_attack_max_completed_sessions is not None:
        cmd += [
            "--desync-attack-max-completed-sessions",
            str(int(sm.desync_attack_max_completed_sessions)),
        ]
    return cmd
