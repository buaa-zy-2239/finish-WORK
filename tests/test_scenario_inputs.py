import json
from pathlib import Path

from Common.scenario_inputs import (
    load_waypoints_from_json_file,
    normalize_link_state_config,
    normalize_auth_trigger_config,
    resolve_config_relative_path,
)


def test_resolve_config_relative_path_uses_config_directory():
    resolved = resolve_config_relative_path("/tmp/project/configs", "traces/uav01.json")
    assert resolved == str(Path("/tmp/project/configs/traces/uav01.json").resolve())


def test_load_waypoints_from_json_file_supports_dict_wrapper(tmp_path):
    path = tmp_path / "trace.json"
    path.write_text(
        json.dumps({"waypoints": [[0, [0, 0, 100]], [5.5, [10, 20, 110]]]}),
        encoding="utf-8",
    )

    assert load_waypoints_from_json_file(str(path)) == [
        [0.0, [0.0, 0.0, 100.0]],
        [5.5, [10.0, 20.0, 110.0]],
    ]


def test_normalize_auth_trigger_config_applies_defaults():
    cfg = normalize_auth_trigger_config({"time_offsets_s": [1, "2.5"], "edge_rssi_threshold": "-83"})

    assert cfg["initial_on_connect"] is True
    assert cfg["allow_reauth"] is False
    assert cfg["on_handover"] is False
    assert cfg["handover_delay_s"] == 0.5
    assert cfg["time_offsets_s"] == [1.0, 2.5]
    assert cfg["edge_rssi_threshold"] == -83.0
    assert cfg["cooldown_s"] == 3.0


def test_normalize_link_state_config_applies_defaults_and_windows():
    cfg = normalize_link_state_config(
        {
            "comm_range_m": "350",
            "edge_rssi_threshold": "-78",
            "loss_windows": [{"start_s": 4, "end_s": 6, "reason": "gap"}],
        }
    )

    assert cfg["comm_range_m"] == 350.0
    assert cfg["edge_rssi_threshold"] == -78.0
    assert cfg["drop_when_out_of_range"] is True
    assert cfg["log_zone_changes"] is True
    assert cfg["uplink_loss_rate"] == 0.0
    assert cfg["loss_windows"] == [{"start_s": 4.0, "end_s": 6.0, "reason": "gap"}]


def test_normalize_link_state_config_clamps_uplink_loss_rate():
    cfg = normalize_link_state_config({"uplink_loss_rate": "1.7"})
    assert cfg["uplink_loss_rate"] == 1.0


def test_normalize_link_state_config_normalizes_uplink_burst_model():
    cfg = normalize_link_state_config(
        {
            "uplink_burst_loss_model": {
                "enabled": True,
                "p_good_to_bad": -1.0,
                "p_bad_to_good": 2.0,
                "loss_good": -0.3,
                "loss_bad": 1.5,
            }
        }
    )
    m = cfg["uplink_burst_loss_model"]
    assert m["enabled"] is True
    assert m["p_good_to_bad"] == 0.0
    assert m["p_bad_to_good"] == 1.0
    assert m["loss_good"] == 0.0
    assert m["loss_bad"] == 1.0
