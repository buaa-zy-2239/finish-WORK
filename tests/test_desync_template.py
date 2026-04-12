import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from Common.desync_attack_template import apply_desync_template  # noqa: E402


def test_uplink_rotation_injects_m3_m4_intercept():
    m = apply_desync_template({"desync_template": "uplink_rotation_drop"})
    assert m["intercept_m3_m4_delivery"] is True
    assert m.get("desync_attack_first_auth_only") is True


def test_explicit_intercept_not_overridden():
    m = apply_desync_template(
        {
            "desync_template": "uplink_rotation_drop",
            "intercept_m3_m4_delivery": False,
        }
    )
    assert m["intercept_m3_m4_delivery"] is False


def test_unknown_template_no_injection():
    m = apply_desync_template({"desync_template": "nonexistent_template"})
    assert "intercept_m3_m4_delivery" not in m or not m.get("intercept_m3_m4_delivery")


def test_downlink_d2z_ack_drop_injects_flag():
    m = apply_desync_template({"desync_template": "downlink_d2z_ack_drop"})
    assert m["intercept_d2z_ack_send"] is True
    assert m.get("desync_attack_first_auth_only") is True


def test_explicit_first_auth_only_false_preserved():
    m = apply_desync_template(
        {
            "desync_template": "uplink_rotation_drop",
            "desync_attack_first_auth_only": False,
        }
    )
    assert m["intercept_m3_m4_delivery"] is True
    assert m["desync_attack_first_auth_only"] is False


def test_legacy_second_arg_ignored():
    """第二参数已废弃，任意值不影响 PMAP M3/M4 展开。"""
    m = apply_desync_template({"desync_template": "uplink_rotation_drop"}, protocol="IGNORED")
    assert m["intercept_m3_m4_delivery"] is True
