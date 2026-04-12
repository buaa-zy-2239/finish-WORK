import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Backend"))

from analysis.protocol_analyzer import D2ZAnalyzer  # noqa: E402
from core.event_models import D2ZEvent, D2ZPhase  # noqa: E402
from core.log_parser import D2ZLogParser  # noqa: E402


def _line(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False) + "\n"


def test_enrich_and_analyzer_counts_d2z_session():
    sid = "test-auth-session-uuid"
    with tempfile.TemporaryDirectory() as d:
        uav_path = os.path.join(d, "sim_1_UAV_0.jsonl")
        zsp_path = os.path.join(d, "sim_1_ZSP_2.jsonl")
        with open(uav_path, "w", encoding="utf-8") as f:
            f.write(
                _line(
                    {
                        "timestamp": 1.0,
                        "sim_time": 0.1,
                        "level": "INFO",
                        "event_type": "AUTHENTICATION_SUCCESS",
                        "entity_type": "UAV",
                        "entity_id": 0,
                        "details": {
                            "phase": "initiated",
                            "status": "success",
                            "peer_id": 2,
                            "auth_session_id": sid,
                            "flow": "D2Z",
                            "protocol_step": "D2Z_INITIATED",
                            "peer_zsp_id": 2,
                            "peer_uav_id": 0,
                        },
                    }
                )
            )
            f.write(
                _line(
                    {
                        "timestamp": 2.0,
                        "sim_time": 0.2,
                        "level": "INFO",
                        "event_type": "MESSAGE_SENT",
                        "entity_type": "UAV",
                        "entity_id": 0,
                        "details": {
                            "message_type": "M1",
                            "payload_size": 100,
                            "peer_id": 2,
                            "auth_session_id": sid,
                            "flow": "D2Z",
                            "peer_zsp_id": 2,
                            "peer_uav_id": 0,
                        },
                    }
                )
            )
            f.write(
                _line(
                    {
                        "timestamp": 5.0,
                        "sim_time": 0.5,
                        "level": "INFO",
                        "event_type": "AUTHENTICATION_SUCCESS",
                        "entity_type": "UAV",
                        "entity_id": 0,
                        "details": {
                            "phase": "success",
                            "status": "success",
                            "peer_id": 2,
                            "auth_session_id": sid,
                            "flow": "D2Z",
                            "peer_zsp_id": 2,
                            "peer_uav_id": 0,
                        },
                    }
                )
            )
        with open(zsp_path, "w", encoding="utf-8") as f:
            f.write(
                _line(
                    {
                        "timestamp": 3.0,
                        "sim_time": 0.3,
                        "level": "INFO",
                        "event_type": "MESSAGE_RECEIVED",
                        "entity_type": "ZSP",
                        "entity_id": 2,
                        "details": {
                            "message_type": "M1",
                            "payload_size": 100,
                            "peer_zsp_id": 2,
                            "peer_uav_id": 0,
                            "flow": "D2Z",
                            "protocol_step": "D2Z_M1_RECV",
                        },
                    }
                )
            )

        events = D2ZLogParser.parse_all_logs(d)
        assert any(e.auth_session_id == sid for e in events)

        an = D2ZAnalyzer(events)
        assert len(an.sessions) >= 1
        s = next(iter(an.sessions.values()))
        assert s.uav_id == 0 and s.zsp_id == 2
        assert s.success
        assert s.m1_size >= 100


def test_zsp_m1_fail_unknown_pid_closes_pending_session_for_metrics():
    """ZSP 记录 UNKNOWN_PID 失败时常无 peer_uav_id；分析器应仍闭合 UAV 侧 pending 会话以便失败数统计。"""
    sid_ok = "sess-ok"
    sid_bad = "sess-bad"
    events = [
        D2ZEvent(
            timestamp=1.0,
            sim_time=1.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.INITIATED,
            auth_session_id=sid_ok,
            flow="D2Z",
            protocol_step="D2Z_INITIATED",
        ),
        D2ZEvent(
            timestamp=2.0,
            sim_time=2.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.SUCCESS,
            auth_session_id=sid_ok,
            flow="D2Z",
            protocol_step="D2Z_SUCCESS",
        ),
        D2ZEvent(
            timestamp=5.0,
            sim_time=5.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.INITIATED,
            auth_session_id=sid_bad,
            flow="D2Z",
            protocol_step="D2Z_ATTACK_RETRY",
        ),
        D2ZEvent(
            timestamp=6.0,
            sim_time=6.0,
            uav_id=-1,
            zsp_id=2,
            phase=D2ZPhase.FAILED,
            success=False,
            error_reason="Unknown error",
            flow="D2Z",
            protocol_step="D2Z_M1_FAIL_UNKNOWN_PID",
        ),
    ]

    an = D2ZAnalyzer(events)
    assert len(an.sessions) == 2
    failed = [s for s in an.sessions.values() if not s.success]
    assert len(failed) == 1
    assert failed[0].auth_session_id == sid_bad
    m = an.get_summary()
    assert m["authentication"]["failed"] == 1
    assert m["authentication"]["successful"] == 1
