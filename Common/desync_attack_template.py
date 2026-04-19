"""
PMAP / PMAP_ACK / RLBA_UAV 去同步攻击模板（`desync_template` → 布尔钩子）。

- `uplink_rotation_drop` → `intercept_m3_m4_delivery`（ZSP 丢弃上行 M3/M4）。
- `downlink_d2z_ack_drop` → `intercept_d2z_ack_send`（**PMAP_ACK**：抑制 **D2Z_ACK**；**RLBA_UAV**：抑制 **SUCCESS**；PMAP 无 ACK 边，该钩子在 ZSP 侧无额外效果。）

`desync_template` 支持**逗号分隔**组合，例如
`uplink_rotation_drop,downlink_d2z_ack_drop`（等价于同时启用两钩）。

默认 `desync_attack_first_auth_only: True`（每 UAV 对每种拦截至多一次，便于「边界扰动 + 后续自恢复」）。

**持续每轮攻击**：在 `attack_model` 中置 `desync_attack_every_round: true`（与 `swarm_unified_scenario_experiment` 的 `--desync-multi-round` 激进模式一致），则 `desync_attack_first_auth_only` 会被置为 **false**。

**边界自恢复实验**：使用模板 `boundary_m3m4_once` / `boundary_ack_once`（每 UAV 有限次），并配合 `--desync-boundary-recovery`（多轮 `allow_reauth` 但 **不** 置 `desync_attack_every_round`）。

**中段单次拦截**：`attack_model.desync_attack_min_completed_sessions`（整数）表示该 UAV 已记录 **D2Z_SUCCESS** 至少这么多次之后，才允许 `intercept_*` 与 `desync_attack_first_auth_only` 生效；与 `swarm` 的 `--reauth-rounds` / `--reauth-spacing-s` 联用可实现「大量正常认证后再去同步」。在 `swarm` 中若省略该字段且为边界自恢复、`--reauth-rounds`≥20，则自动取约半数轮次对应的阈值；轮次很少时默认 0（与早期「首轮可拦」语义一致）。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# 模板 id -> 注入的标志（仅当 attack_model 中未显式给出同名字段时写入）
_TEMPLATE_INJECT: Dict[str, Dict[str, Any]] = {
    "uplink_rotation_drop": {"intercept_m3_m4_delivery": True},
    "downlink_d2z_ack_drop": {"intercept_d2z_ack_send": True},
    # 边界型：仅作用在「更新与确认」单侧，且依赖 first_auth_only 做有限次干扰
    "boundary_m3m4_once": {
        "intercept_m3_m4_delivery": True,
        "intercept_d2z_ack_send": False,
    },
    "boundary_ack_once": {
        "intercept_m3_m4_delivery": False,
        "intercept_d2z_ack_send": True,
    },
}


def _merge_template_fragments(tokens: list[str]) -> Dict[str, Any]:
    """合并多个模板片段；布尔键按 OR 合并（任一模板要求 True 则为 True）。"""
    merged: Dict[str, Any] = {}
    for raw in tokens:
        t = raw.strip().lower().replace("-", "_")
        if not t:
            continue
        frag = _TEMPLATE_INJECT.get(t)
        if not frag:
            continue
        for k, v in frag.items():
            if isinstance(v, bool) and isinstance(merged.get(k), bool):
                merged[k] = bool(merged[k] or v)
            else:
                merged[k] = v
    return merged


def apply_desync_template(
    attack_model: Dict[str, Any],
    protocol: Optional[str] = None,
) -> Dict[str, Any]:
    """
    将 `desync_template` 展开为攻击标志（不覆盖已显式给出的同名字段）。

    支持逗号分隔的多模板；`protocol` 参数已废弃。
    """
    del protocol  # 兼容旧签名，不再分支
    out = dict(attack_model or {})
    tid = (out.get("desync_template") or "").strip().lower().replace("-", "_")
    if not tid:
        return out
    tokens = [x.strip() for x in tid.split(",") if x.strip()]
    extra = _merge_template_fragments(tokens)
    if not extra:
        return out
    for k, v in extra.items():
        if k not in out:
            out[k] = v

    if out.get("desync_attack_every_round"):
        out["desync_attack_first_auth_only"] = False
    elif "desync_attack_first_auth_only" not in out:
        out["desync_attack_first_auth_only"] = True
    return out


def list_desync_templates() -> Dict[str, str]:
    """可用模板 id -> 说明（前端/文档）。"""
    return {
        "uplink_rotation_drop": "ZSP 丢弃上行 M3/M4（intercept_m3_m4_delivery）；默认仅第一次尝试",
        "downlink_d2z_ack_drop": "PMAP_ACK：不发送 D2Z_ACK；RLBA_UAV：不发送 SUCCESS；均用 intercept_d2z_ack_send；默认仅第一次尝试",
        "uplink_rotation_drop,downlink_d2z_ack_drop": "组合：上行 M3/M4 丢弃 + 下行 ACK/SUCCESS 抑制（逗号分隔）",
        "boundary_m3m4_once": "边界：仅首轮/每机一次上行 M3/M4 丢弃（配合 first_auth_only）",
        "boundary_ack_once": "边界：仅首轮/每机一次下行 ACK（或 RLBA SUCCESS）抑制（配合 first_auth_only）",
    }
