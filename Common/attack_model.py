"""
Attack / security evaluation helpers for the PMAP simulation.

The simulator does not add a separate attacker node.  Many channel-level
attacks are modeled by **dropping or altering messages** inside legitimate
entities (ZSP / UAV) when `attack_model` flags are set.

**协议无关去同步模板**  
见 `Common/desync_attack_template.py`：在 `attack_model` 中设置 `desync_template`，
支持 `uplink_rotation_drop`、`downlink_d2z_ack_drop` 等，见 `desync_attack_template.py`。
"""


def merge_attack_model(config: dict) -> dict:
    """
    Merge attack flags from `security_profile.attack_model` and top-level
    `attack_model`.  Top-level keys win on conflict.
    """
    sec = config.get("security_profile") or {}
    merged = dict(sec.get("attack_model") or {})
    top = config.get("attack_model") or {}
    out = {**merged, **top}
    for bkey in (
        "intercept_m3_m4_delivery",
        "intercept_d2z_ack_send",
        "desync_attack_first_auth_only",
        "replay_m2_after_m1",
        "forge_m1_bad_mac",
    ):
        if bkey in out:
            out[bkey] = bool(out[bkey])
    if out.get("retry_d2z_after_intercept_s") is not None:
        out["retry_d2z_after_intercept_s"] = float(out["retry_d2z_after_intercept_s"])
    if out.get("d2z_ack_timeout_s") is not None:
        out["d2z_ack_timeout_s"] = float(out["d2z_ack_timeout_s"])
    return out
