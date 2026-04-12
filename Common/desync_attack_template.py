"""
PMAP / PMAP_ACK 去同步攻击模板（仿真用 `desync_template` 展开为布尔钩子）。

- `uplink_rotation_drop` → `intercept_m3_m4_delivery`（ZSP 丢弃上行 M3/M4）。
- `downlink_d2z_ack_drop` → `intercept_d2z_ack_send`（仅 **PMAP_ACK** 有意义：ZSP 验证 M3/M4 后抑制发送 D2Z_ACK，地面库不更新，便于检验会话冗余）。

使用模板时默认注入 `desync_attack_first_auth_only: True`：去同步**仅针对每架 UAV 的第一次 M3/M4 认证尝试**（首次丢弃/首次拦 ACK），之后与无攻击一致，便于展示重试与恢复。若需每次认证都攻击，在 `attack_model` 中显式设置 `desync_attack_first_auth_only: false`。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# 模板 id -> 注入的标志（仅当 attack_model 中未显式给出同名字段时写入）
_TEMPLATE_INJECT: Dict[str, Dict[str, Any]] = {
    "uplink_rotation_drop": {"intercept_m3_m4_delivery": True},
    "downlink_d2z_ack_drop": {"intercept_d2z_ack_send": True},
}


def apply_desync_template(
    attack_model: Dict[str, Any],
    protocol: Optional[str] = None,
) -> Dict[str, Any]:
    """
    将 `desync_template` 展开为上述攻击标志（不覆盖已显式给出的同名字段）。

    `protocol` 参数已废弃，仅为旧调用兼容。
    """
    del protocol  # 兼容旧签名，不再分支
    out = dict(attack_model or {})
    tid = (out.get("desync_template") or "").strip().lower().replace("-", "_")
    if not tid:
        return out
    extra = _TEMPLATE_INJECT.get(tid)
    if extra is None:
        return out
    for k, v in extra.items():
        if k not in out:
            out[k] = v
    if "desync_attack_first_auth_only" not in out:
        out["desync_attack_first_auth_only"] = True
    return out


def list_desync_templates() -> Dict[str, str]:
    """可用模板 id -> 说明（前端/文档）。"""
    return {
        "uplink_rotation_drop": "ZSP 丢弃上行 M3/M4（intercept_m3_m4_delivery）；默认仅第一次尝试",
        "downlink_d2z_ack_drop": "PMAP_ACK：ZSP 验证 M3/M4 后不发送 D2Z_ACK（intercept_d2z_ack_send）；默认仅第一次尝试",
    }
