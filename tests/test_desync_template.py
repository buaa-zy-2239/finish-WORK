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


def test_comma_separated_template_merges_flags():
    m = apply_desync_template(
        {"desync_template": "uplink_rotation_drop,downlink_d2z_ack_drop"}
    )
    assert m["intercept_m3_m4_delivery"] is True
    assert m["intercept_d2z_ack_send"] is True
    assert m.get("desync_attack_first_auth_only") is True


def test_desync_attack_every_round_forces_persistent_attack():
    m = apply_desync_template(
        {
            "desync_template": "uplink_rotation_drop",
            "desync_attack_every_round": True,
        }
    )
    assert m["intercept_m3_m4_delivery"] is True
    assert m["desync_attack_first_auth_only"] is False


def test_boundary_ack_once_keeps_first_auth_only():
    m = apply_desync_template({"desync_template": "boundary_ack_once"})
    assert m["intercept_d2z_ack_send"] is True
    assert not m.get("intercept_m3_m4_delivery")
    assert m.get("desync_attack_first_auth_only") is True


def test_boundary_recovery_multi_round_does_not_force_persistent():
    m = apply_desync_template(
        {
            "desync_template": "boundary_ack_once",
            "desync_multi_round": True,
            "desync_attack_every_round": False,
        }
    )
    assert m["intercept_d2z_ack_send"] is True
    assert m.get("desync_attack_first_auth_only") is True
