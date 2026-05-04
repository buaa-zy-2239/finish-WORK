import json
from pathlib import Path


def resolve_config_relative_path(base_dir: str | None, raw_path: str | None) -> str | None:
    if not raw_path:
        return None
    p = Path(raw_path)
    if p.is_absolute() or base_dir is None:
        return str(p)
    return str((Path(base_dir) / p).resolve())


def load_waypoints_from_json_file(path: str) -> list[list]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    waypoints = data.get("waypoints") if isinstance(data, dict) else data
    if not isinstance(waypoints, list):
        raise ValueError("Trajectory file must contain a list or {'waypoints': [...]} structure")

    normalized = []
    for idx, item in enumerate(waypoints):
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ValueError(f"Waypoint #{idx} must be [time, [x, y, z]]")
        t, pos = item
        if not isinstance(pos, (list, tuple)) or len(pos) != 3:
            raise ValueError(f"Waypoint #{idx} position must be [x, y, z]")
        normalized.append([float(t), [float(pos[0]), float(pos[1]), float(pos[2])]])
    return normalized


def normalize_auth_trigger_config(conf: dict | None) -> dict:
    cfg = dict(conf or {})
    time_offsets = cfg.get("time_offsets_s") or []
    cfg["time_offsets_s"] = [float(v) for v in time_offsets]
    cfg["initial_on_connect"] = bool(cfg.get("initial_on_connect", True))
    cfg["allow_reauth"] = bool(cfg.get("allow_reauth", False))
    cfg["on_handover"] = bool(cfg.get("on_handover", False))
    cfg["handover_delay_s"] = float(cfg.get("handover_delay_s", 0.5))
    if cfg.get("edge_rssi_threshold") is not None:
        cfg["edge_rssi_threshold"] = float(cfg["edge_rssi_threshold"])
    cfg["cooldown_s"] = float(cfg.get("cooldown_s", 3.0))
    return cfg


def normalize_link_state_config(conf: dict | None) -> dict:
    cfg = dict(conf or {})
    if cfg.get("comm_range_m") is not None:
        cfg["comm_range_m"] = float(cfg["comm_range_m"])
    if cfg.get("edge_rssi_threshold") is not None:
        cfg["edge_rssi_threshold"] = float(cfg["edge_rssi_threshold"])
    cfg["drop_when_out_of_range"] = bool(cfg.get("drop_when_out_of_range", True))
    cfg["log_zone_changes"] = bool(cfg.get("log_zone_changes", True))
    if cfg.get("uplink_loss_rate") is not None:
        cfg["uplink_loss_rate"] = max(0.0, min(1.0, float(cfg["uplink_loss_rate"])))
    else:
        cfg["uplink_loss_rate"] = 0.0
    burst_model = dict(cfg.get("uplink_burst_loss_model") or {})
    burst_model["enabled"] = bool(burst_model.get("enabled", False))
    burst_model["p_good_to_bad"] = max(0.0, min(1.0, float(burst_model.get("p_good_to_bad", 0.02))))
    burst_model["p_bad_to_good"] = max(0.0, min(1.0, float(burst_model.get("p_bad_to_good", 0.25))))
    burst_model["loss_good"] = max(0.0, min(1.0, float(burst_model.get("loss_good", 0.01))))
    burst_model["loss_bad"] = max(0.0, min(1.0, float(burst_model.get("loss_bad", 0.75))))
    cfg["uplink_burst_loss_model"] = burst_model
    # 处理loss_windows
    windows = []
    for idx, item in enumerate(cfg.get("loss_windows", []) or []):
        if not isinstance(item, dict):
            raise ValueError(f"loss_windows[{idx}] must be an object")
        start = float(item.get("start_s", 0.0))
        end = float(item.get("end_s", start))
        windows.append(
            {
                "start_s": start,
                "end_s": end,
                "reason": item.get("reason", "scheduled_loss_window"),
            }
        )
    cfg["loss_windows"] = windows
    return cfg
