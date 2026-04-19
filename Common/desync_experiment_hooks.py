"""
去同步实验可观测钩子：在 ZSP/UAV 完成 PID 数据库或本地更新后打点，
便于多轮认证下统计「地面站已更新 / 机端已切换」的时序与次数。

仅当 attack_model.desync_experiment_enabled 为真时输出日志；
不改变协议状态（与 PMAPZSP/RLBAZSP 中基于 attack_model 的拦截逻辑正交）。
"""

from __future__ import annotations

from typing import Any, Optional


def emit_desync_pid_transition(
    entity: Any,
    side: str,
    source: str,
    *,
    old_pid: Optional[str],
    new_pid: Optional[str],
) -> None:
    """
    side: "zsp" | "uav"
    source: 调用点语义标签，如 UpdateUAVPID / blockchain_event / pmap_after_m3m4 / pmap_ack_apply
    """
    am = getattr(entity, "attack_model", None) or {}
    if not am.get("desync_experiment_enabled"):
        return
    logger = getattr(entity, "logger", None)
    if logger is None:
        return
    key = "_desync_obs_round"
    r = int(getattr(entity, key, 0) or 0) + 1
    setattr(entity, key, r)
    extra = {
        "protocol": getattr(entity, "protocol_name", None),
        "analysis_family": getattr(entity, "analysis_family", None),
        "flow": "D2Z",
        "protocol_step": "DESYNC_EXPERIMENT_PID_TRANSITION",
        "desync_side": side,
        "desync_source": source,
        "desync_obs_index": r,
        "old_pid_prefix": (old_pid or "")[:16],
        "new_pid_prefix": (new_pid or "")[:16],
        "peer_zsp_id": getattr(entity, "zsp_id", None),
        "peer_uav_id": getattr(entity, "id", None),
    }
    logger.log_warning(
        f"desync experiment: {side} PID transition ({source})",
        warning_type="desync_experiment_pid_transition",
        extra=extra,
    )
