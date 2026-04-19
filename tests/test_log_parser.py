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
    key_h = "deadbeef" * 8
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
            timestamp=1.5,
            sim_time=1.5,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.SESSION_KEY_ESTABLISHED,
            auth_session_id=sid_ok,
            session_key_hash=key_h,
            entity_type="UAV",
            flow="D2Z",
            protocol_step="D2Z_SESSION_KEY",
        ),
        D2ZEvent(
            timestamp=1.51,
            sim_time=1.51,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.SESSION_KEY_ESTABLISHED,
            auth_session_id=sid_ok,
            session_key_hash=key_h,
            entity_type="ZSP",
            flow="D2Z",
            protocol_step="D2Z_SESSION_KEY",
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
            protocol_step="D2Z_INITIATED_BAD",
        ),
        D2ZEvent(
            timestamp=6.0,
            sim_time=6.0,
            uav_id=-1,
            zsp_id=2,
            phase=D2ZPhase.FAILED,
            success=False,
            error_reason="unknown_pid",
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


def test_parse_zsp_jsonl_unknown_pid_m1_emits_auth_failed_event():
    """ZSP 侧 M1 未知 PID 须产生 AUTHENTICATION_FAILED，便于解析器计入显式失败（非仅 ERROR）。"""
    line = _line(
        {
            "timestamp": 10.0,
            "sim_time": 5.0,
            "level": "WARNING",
            "event_type": "AUTHENTICATION_FAILED",
            "entity_type": "ZSP",
            "entity_id": 2,
            "details": {
                "phase": "failed",
                "status": "failed",
                "peer_id": None,
                "protocol": "PMAP",
                "analysis_family": "D2Z",
                "flow": "D2Z",
                "peer_zsp_id": 2,
                "peer_uav_id": None,
                "protocol_step": "D2Z_M1_FAIL_UNKNOWN_PID",
                "error_reason": "unknown_pid",
            },
        }
    )
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "sim_1_ZSP_2.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            f.write(line)
        events = D2ZLogParser.parse_all_logs(d)
    assert len(events) == 1
    assert events[0].phase == D2ZPhase.FAILED
    assert events[0].success is False
    assert events[0].protocol_step == "D2Z_M1_FAIL_UNKNOWN_PID"
    assert events[0].error_reason == "unknown_pid"


def test_retry_after_ack_timeout_creates_new_auth_session():
    """ACK 超时后重试应开启新的 auth_session_id，并形成独立失败/成功会话。"""
    sid_timeout = "sess-timeout"
    sid_success = "sess-success"
    events = [
        D2ZEvent(
            timestamp=1.0,
            sim_time=1.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.INITIATED,
            auth_session_id=sid_timeout,
            flow="D2Z",
            protocol_step="D2Z_INITIATED",
        ),
        D2ZEvent(
            timestamp=2.0,
            sim_time=2.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.FAILED,
            auth_session_id=sid_timeout,
            success=False,
            error_reason="d2z_ack_timeout",
            flow="D2Z",
            protocol_step="D2Z_ACK_TIMEOUT",
        ),
        D2ZEvent(
            timestamp=3.0,
            sim_time=3.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.INITIATED,
            auth_session_id=sid_success,
            flow="D2Z",
            protocol_step="D2Z_INITIATED_POST_TIMEOUT",
        ),
        D2ZEvent(
            timestamp=4.0,
            sim_time=4.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.SUCCESS,
            auth_session_id=sid_success,
            flow="D2Z",
            protocol_step="D2Z_SUCCESS",
        ),
    ]

    an = D2ZAnalyzer(events)
    assert len(an.sessions) == 2
    by_sid = {s.auth_session_id: s for s in an.sessions.values()}
    assert by_sid[sid_timeout].success is False
    assert by_sid[sid_timeout].error_reason == "d2z_ack_timeout"
    assert by_sid[sid_success].success is True


def test_log_parser_keeps_retry_and_success_as_separate_timelines():
    """解析器应把 ACK 超时后的重试识别为新会话，不与上一轮 pending ACK 混淆。"""
    sid_timeout = "ack-timeout-round"
    sid_success = "ack-retry-round"
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
                            "auth_session_id": sid_timeout,
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
                        "level": "ERROR",
                        "event_type": "MESSAGE_ERROR",
                        "entity_type": "UAV",
                        "entity_id": 0,
                        "details": {
                            "message_type": "UNKNOWN",
                            "payload_size": 145,
                            "error_reason": "d2z_ack_timeout",
                            "auth_session_id": sid_timeout,
                            "flow": "D2Z",
                            "protocol_step": "D2Z_ACK_TIMEOUT",
                            "peer_zsp_id": 2,
                            "peer_uav_id": 0,
                        },
                    }
                )
            )
            f.write(
                _line(
                    {
                        "timestamp": 3.0,
                        "sim_time": 0.3,
                        "level": "INFO",
                        "event_type": "AUTHENTICATION_SUCCESS",
                        "entity_type": "UAV",
                        "entity_id": 0,
                        "details": {
                            "phase": "initiated",
                            "status": "success",
                            "peer_id": 2,
                            "auth_session_id": sid_success,
                            "flow": "D2Z",
                            "protocol_step": "D2Z_RETRY_AFTER_ACK_TIMEOUT",
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
                            "auth_session_id": sid_success,
                            "flow": "D2Z",
                            "protocol_step": "D2Z_SUCCESS",
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
                        "timestamp": 4.0,
                        "sim_time": 0.4,
                        "level": "INFO",
                        "event_type": "MESSAGE_SENT",
                        "entity_type": "ZSP",
                        "entity_id": 2,
                        "details": {
                            "message_type": "D2Z_ACK",
                            "payload_size": 145,
                            "flow": "D2Z",
                            "protocol_step": "D2Z_ACK_SEND",
                            "peer_zsp_id": 2,
                            "peer_uav_id": 0,
                        },
                    }
                )
            )

        events = D2ZLogParser.parse_all_logs(d)
        an = D2ZAnalyzer(events)
        assert len(an.sessions) == 2
        sessions = {s.auth_session_id: s for s in an.sessions.values()}
        assert sessions[sid_timeout].success is False
        assert sessions[sid_success].success is True

        retry_timeline = an.get_session_timeline(0, 2, sid_success)
        retry_steps = [e["protocol_step"] for e in retry_timeline]
        assert "D2Z_RETRY_AFTER_ACK_TIMEOUT" in retry_steps
        assert "D2Z_SUCCESS" in retry_steps
        assert "D2Z_ACK_TIMEOUT" not in retry_steps


def test_analyzer_exposes_trigger_reason_and_breakdown():
    events = [
        D2ZEvent(
            timestamp=1.0,
            sim_time=1.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.INITIATED,
            auth_session_id="sid-edge",
            flow="D2Z",
            protocol_step="D2Z_TRIGGER_EDGE_RSSI",
        ),
        D2ZEvent(
            timestamp=2.0,
            sim_time=2.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.SUCCESS,
            auth_session_id="sid-edge",
            flow="D2Z",
            protocol_step="D2Z_SUCCESS",
        ),
        D2ZEvent(
            timestamp=3.0,
            sim_time=3.0,
            uav_id=1,
            zsp_id=2,
            phase=D2ZPhase.INITIATED,
            auth_session_id="sid-time",
            flow="D2Z",
            protocol_step="D2Z_TRIGGER_TIME",
        ),
        D2ZEvent(
            timestamp=4.0,
            sim_time=4.0,
            uav_id=1,
            zsp_id=2,
            phase=D2ZPhase.FAILED,
            auth_session_id="sid-time",
            flow="D2Z",
            success=False,
            error_reason="timeout",
            protocol_step="D2Z_ACK_TIMEOUT",
        ),
    ]

    analyzer = D2ZAnalyzer(events)
    sessions = {s.auth_session_id: s.to_dict() for s in analyzer.sessions.values()}
    assert sessions["sid-edge"]["trigger_reason"] == "edge_rssi"
    assert sessions["sid-edge"]["trigger_step"] == "D2Z_TRIGGER_EDGE_RSSI"
    assert sessions["sid-time"]["trigger_reason"] == "time_window"

    summary = analyzer.get_summary()
    assert summary["triggers"]["breakdown"] == {
        "edge_rssi": 1,
        "time_window": 1,
    }


def test_analyzer_exposes_mechanism_metrics():
    events = [
        D2ZEvent(
            timestamp=1.0,
            sim_time=1.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.INITIATED,
            auth_session_id="fail-round",
            flow="D2Z",
            protocol_step="D2Z_TRIGGER_EDGE_RSSI",
            distance_m=120.0,
            rssi=-75.0,
            link_zone="edge",
        ),
        D2ZEvent(
            timestamp=2.0,
            sim_time=2.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.FAILED,
            auth_session_id="fail-round",
            success=False,
            error_reason="timeout",
            flow="D2Z",
            protocol_step="D2Z_ACK_TIMEOUT",
        ),
        D2ZEvent(
            timestamp=3.0,
            sim_time=3.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.INITIATED,
            auth_session_id="retry-round",
            flow="D2Z",
            protocol_step="D2Z_RETRY_AFTER_ACK_TIMEOUT",
            distance_m=140.0,
            rssi=-74.0,
            link_zone="edge",
        ),
        D2ZEvent(
            timestamp=4.0,
            sim_time=4.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.M1_SENT,
            auth_session_id="retry-round",
            message_type="M1",
            payload_size=100,
        ),
        D2ZEvent(
            timestamp=5.0,
            sim_time=5.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.SUCCESS,
            auth_session_id="retry-round",
            flow="D2Z",
            protocol_step="D2Z_SUCCESS",
        ),
        D2ZEvent(
            timestamp=6.0,
            sim_time=6.0,
            uav_id=1,
            zsp_id=2,
            phase=D2ZPhase.INITIATED,
            auth_session_id="baseline-success",
            flow="D2Z",
            protocol_step="D2Z_INITIATED",
            distance_m=30.0,
            rssi=-60.0,
            link_zone="core",
        ),
        D2ZEvent(
            timestamp=7.0,
            sim_time=7.0,
            uav_id=1,
            zsp_id=2,
            phase=D2ZPhase.M1_SENT,
            auth_session_id="baseline-success",
            message_type="M1",
            payload_size=80,
        ),
        D2ZEvent(
            timestamp=8.0,
            sim_time=8.0,
            uav_id=1,
            zsp_id=2,
            phase=D2ZPhase.SUCCESS,
            auth_session_id="baseline-success",
            flow="D2Z",
            protocol_step="D2Z_SUCCESS",
        ),
    ]

    analyzer = D2ZAnalyzer(events)
    summary = analyzer.get_summary()
    assert summary["mechanism"]["recovery_completion_ratio"] == 1.0
    assert summary["mechanism"]["reauthentication_cost"]["retry_successes"] == 1
    assert summary["mechanism"]["success_vs_distance"] == [
        {
            "bucket": "0-50m",
            "total_sessions": 1,
            "successful_sessions": 1,
            "success_rate_percent": 100.0,
        },
        {
            "bucket": "100-150m",
            "total_sessions": 2,
            "successful_sessions": 1,
            "success_rate_percent": 50.0,
        },
    ]


def test_log_parser_preserves_protocol_labels_and_static_steps():
    sid = "static-baseline-sid"
    raw = {
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
            "protocol": "STATIC_BASELINE",
            "analysis_family": "D2Z",
            "protocol_step": "STATIC_INIT",
            "peer_zsp_id": 2,
            "peer_uav_id": 0,
        },
    }

    event = D2ZLogParser._extract_d2z_event(raw)
    assert event is not None
    assert event.phase == D2ZPhase.INITIATED
    assert event.protocol == "STATIC_BASELINE"
    assert event.analysis_family == "D2Z"


def test_log_parser_accepts_rlba_events_under_d2z_family():
    sid = "rlba-sid"
    events = [
        D2ZEvent(
            timestamp=1.0,
            sim_time=1.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.INITIATED,
            auth_session_id=sid,
            flow="D2Z",
            protocol="RLBA_UAV",
            analysis_family="D2Z",
            protocol_step="D2Z_INITIATED",
        ),
        D2ZEvent(
            timestamp=2.0,
            sim_time=2.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.M1_SENT,
            auth_session_id=sid,
            message_type="M1",
            payload_size=120,
            protocol="RLBA_UAV",
            analysis_family="D2Z",
            protocol_step="RLBA_INIT",
        ),
        D2ZEvent(
            timestamp=3.0,
            sim_time=3.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.M2_RECEIVED,
            auth_session_id=sid,
            message_type="M2",
            payload_size=140,
            protocol="RLBA_UAV",
            analysis_family="D2Z",
            protocol_step="RLBA_CHALLENGE",
        ),
        D2ZEvent(
            timestamp=4.0,
            sim_time=4.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.M3_M4_SENT,
            auth_session_id=sid,
            message_type="M3",
            payload_size=160,
            protocol="RLBA_UAV",
            analysis_family="D2Z",
            protocol_step="RLBA_RESPONSE",
        ),
        D2ZEvent(
            timestamp=5.0,
            sim_time=5.0,
            uav_id=0,
            zsp_id=2,
            phase=D2ZPhase.SUCCESS,
            auth_session_id=sid,
            flow="D2Z",
            protocol="RLBA_UAV",
            analysis_family="D2Z",
            protocol_step="RLBA_SUCCESS",
        ),
    ]

    analyzer = D2ZAnalyzer(events)
    session = next(iter(analyzer.sessions.values()))
    assert session.protocol == "RLBA_UAV"
    assert session.message_count >= 3
    assert session.success is True
