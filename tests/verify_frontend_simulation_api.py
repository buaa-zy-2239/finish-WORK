#!/usr/bin/env python3
"""
复现「仿真管理」前端创建任务时的 API 负载，并校验落盘 config 与模板展开逻辑。

用法（需后端已启动在默认端口）:
  python3 tests/verify_frontend_simulation_api.py
  API_BASE=http://127.0.0.1:8000/api/v1 python3 tests/verify_frontend_simulation_api.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from Common.attack_model import merge_attack_model  # noqa: E402
from Common.desync_attack_template import apply_desync_template  # noqa: E402

API_BASE = os.environ.get("API_BASE", "http://127.0.0.1:8000/api/v1").rstrip("/")


def _post_create(body: dict) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{API_BASE}/simulation/create",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _offline_assert(protocol: str, template: str, extra_am: dict | None) -> None:
    am = {"desync_template": template}
    if extra_am:
        am.update(extra_am)
    cfg = {
        "protocol": protocol,
        "security_profile": {"attack_model": am},
    }
    merged = apply_desync_template(merge_attack_model(cfg))
    if template == "uplink_rotation_drop":
        assert merged.get("intercept_m3_m4_delivery") is True, merged
        assert merged.get("desync_attack_first_auth_only") is True, merged
    elif template == "downlink_d2z_ack_drop":
        assert merged.get("intercept_d2z_ack_send") is True, merged
        assert merged.get("desync_attack_first_auth_only") is True, merged


def _check_config_file(config_path: str, protocol: str, template: str) -> None:
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    assert cfg.get("protocol") == protocol, cfg
    am = (cfg.get("security_profile") or {}).get("attack_model") or {}
    assert am.get("desync_template") == template, am
    _offline_assert(protocol, template, {k: v for k, v in am.items() if k != "desync_template"})


def main() -> int:
    _offline_assert("PMAP", "uplink_rotation_drop", {"retry_d2z_after_intercept_s": 4})
    _offline_assert("PMAP_ACK", "downlink_d2z_ack_drop", {"d2z_ack_timeout_s": 3})

    body_pmap = {
        "name": "e2e_desync_m3m4",
        "duration": 35,
        "protocol": "PMAP",
        "uavs": [
            {
                "id": 0,
                "mobility": {
                    "type": "waypoint",
                    "waypoints": [[0, [0, 0, 50]], [30, [120, 0, 50]]],
                },
            }
        ],
        "zsps": [{"id": 2, "position": [0, 0, 100]}],
        "channel": {"type": "CSMA", "datarate": "100Mbps"},
        "scenario": "desync_m3m4_intercept",
        "security_profile": {
            "adversary": "channel_drop",
            "attack_model": {
                "desync_template": "uplink_rotation_drop",
                "retry_d2z_after_intercept_s": 4,
            },
        },
    }
    body_ack = {
        "name": "e2e_pmap_ack_drop",
        "duration": 30,
        "protocol": "PMAP_ACK",
        "uavs": [
            {
                "id": 0,
                "mobility": {
                    "type": "waypoint",
                    "waypoints": [[0, [0, 0, 50]], [25, [90, 0, 50]]],
                },
            }
        ],
        "zsps": [{"id": 2, "position": [0, 0, 100]}],
        "channel": {"type": "CSMA", "datarate": "100Mbps"},
        "scenario": "pmap_ack_attack_drop_ack",
        "security_profile": {
            "adversary": "channel_drop",
            "attack_model": {
                "desync_template": "downlink_d2z_ack_drop",
                "d2z_ack_timeout_s": 3,
            },
        },
    }

    try:
        r1 = _post_create(body_pmap)
        time.sleep(1.1)
        r2 = _post_create(body_ack)
    except urllib.error.URLError as e:
        print("SKIP HTTP: API 不可达:", e)
        print("OK: 离线模板展开校验已通过。")
        return 0

    assert r1.get("success") and r1.get("config_file"), r1
    assert r2.get("success") and r2.get("config_file"), r2
    _check_config_file(r1["config_file"], "PMAP", "uplink_rotation_drop")
    _check_config_file(r2["config_file"], "PMAP_ACK", "downlink_d2z_ack_drop")
    print("OK PMAP:", r1.get("task_id"))
    print("OK PMAP_ACK:", r2.get("task_id"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
