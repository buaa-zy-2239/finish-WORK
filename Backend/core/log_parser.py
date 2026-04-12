# Backend/core/log_parser.py
"""
日志解析器 - D2Z 流程（支持 auth_session_id / 双向实体关联）
"""

import json
import glob
import os
from typing import Any, Dict, List, Optional, Tuple

from .event_models import D2ZEvent, D2ZPhase


class D2ZLogParser:
    """D2Z流程日志解析器"""

    D2Z_EVENT_TYPES = {
        "AUTHENTICATION_SUCCESS": "auth",
        "AUTHENTICATION_FAILED": "auth",
        "MESSAGE_SENT": "message",
        "MESSAGE_RECEIVED": "message",
        "MESSAGE_ERROR": "error",
        "SESSION_ESTABLISHED": "session",
    }

    @staticmethod
    def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
        """解析单行日志"""
        try:
            data = json.loads(line.strip())
            required_fields = [
                "timestamp",
                "sim_time",
                "level",
                "event_type",
                "entity_type",
                "entity_id",
                "details",
            ]
            if not all(field in data for field in required_fields):
                return None
            return data
        except (json.JSONDecodeError, ValueError, KeyError):
            return None

    @staticmethod
    def _resolve_ids(
        entity_type: str, entity_id: int, details: Dict[str, Any]
    ) -> Tuple[int, Optional[int]]:
        """解析逻辑 UAV / ZSP id（ZSP 文件中的 entity_id 为 ZSP）。"""
        peer_zsp = details.get("peer_zsp_id", details.get("peer_id"))
        peer_uav = details.get("peer_uav_id", details.get("uav_id"))

        if entity_type == "UAV":
            uav_id = int(entity_id)
            zsp_id = peer_zsp
            if zsp_id is not None:
                try:
                    zsp_id = int(zsp_id)
                except (TypeError, ValueError):
                    zsp_id = None
            return uav_id, zsp_id

        if entity_type == "ZSP":
            zsp_id = int(entity_id)
            uav_id = -1
            pu = peer_uav
            if pu is None and details.get("peer_id") is not None:
                pu = details.get("peer_id")
            if pu is not None:
                try:
                    uav_id = int(pu)
                except (TypeError, ValueError):
                    uav_id = -1
            return uav_id, zsp_id

        return int(entity_id), peer_zsp

    @staticmethod
    def _extract_d2z_event(raw_data: Dict[str, Any]) -> Optional[D2ZEvent]:
        """从原始日志数据提取D2Z事件"""
        event_type = raw_data.get("event_type", "")
        if event_type not in D2ZLogParser.D2Z_EVENT_TYPES:
            return None

        entity_type = raw_data.get("entity_type", "")
        timestamp = float(raw_data.get("timestamp", 0.0))
        sim_time = float(raw_data.get("sim_time", 0.0))
        entity_id = raw_data.get("entity_id", 0)
        details = raw_data.get("details", {}) or {}

        uav_id, zsp_id = D2ZLogParser._resolve_ids(entity_type, entity_id, details)

        phase: Optional[D2ZPhase] = None
        message_type: Optional[str] = None
        payload_size: Optional[int] = None
        success = True
        error_reason: Optional[str] = None
        session_key_hash: Optional[str] = None
        auth_session_id = details.get("auth_session_id")
        flow = details.get("flow")
        protocol_step = details.get("protocol_step")

        if event_type == "AUTHENTICATION_SUCCESS":
            auth_phase = details.get("phase", "")
            if auth_phase == "initiated":
                phase = D2ZPhase.INITIATED
            elif auth_phase == "message_sent":
                phase = D2ZPhase.M1_SENT
                message_type = details.get("message_type")
                payload_size = details.get("payload_size")
            elif auth_phase == "success":
                phase = D2ZPhase.SUCCESS
                session_key_hash = details.get("session_key_hash")
            else:
                return None

        elif event_type == "AUTHENTICATION_FAILED":
            phase = D2ZPhase.FAILED
            success = False
            error_reason = details.get("error_reason") or details.get("error_message") or "Unknown error"

        elif event_type == "MESSAGE_ERROR":
            phase = D2ZPhase.FAILED
            success = False
            message_type = details.get("message_type")
            payload_size = details.get("payload_size")
            error_reason = details.get("error_reason", "message_error")
            protocol_step = protocol_step or "MESSAGE_ERROR"

        elif event_type == "MESSAGE_SENT":
            message_type = details.get("message_type", "") or ""
            payload_size = int(details.get("payload_size", 0) or 0)
            if message_type == "M1":
                phase = D2ZPhase.M1_SENT
            elif message_type == "M2":
                phase = D2ZPhase.M2_SENT
            elif message_type in ("M3", "M4", "M3_M4", "M3_4"):
                phase = D2ZPhase.M3_M4_SENT
            else:
                return None

        elif event_type == "MESSAGE_RECEIVED":
            message_type = details.get("message_type", "") or ""
            payload_size = int(details.get("payload_size", 0) or 0)
            if message_type == "M1":
                phase = D2ZPhase.M1_RECEIVED
            elif message_type == "M2":
                phase = D2ZPhase.M2_RECEIVED
            elif message_type in ("M3", "M4", "M3_M4", "M3_4"):
                phase = D2ZPhase.M3_M4_SENT
            else:
                return None

        elif event_type == "SESSION_ESTABLISHED":
            phase = D2ZPhase.SESSION_KEY_ESTABLISHED
            session_key_hash = details.get("session_key_hash")

        if phase is None:
            return None

        return D2ZEvent(
            timestamp=timestamp,
            sim_time=sim_time,
            uav_id=uav_id,
            zsp_id=zsp_id,
            phase=phase,
            message_type=message_type,
            payload_size=payload_size,
            success=success,
            error_reason=error_reason,
            session_key_hash=session_key_hash,
            auth_session_id=auth_session_id,
            flow=flow,
            protocol_step=protocol_step,
        )

    @staticmethod
    def enrich_auth_session_ids(events: List[D2ZEvent]) -> None:
        """
        将 UAV 在 INITIATED 中产生的 auth_session_id 关联到同一 (uav_id, zsp_id) 的后续事件
        （含 ZSP 侧日志）。新一轮认证由新的 INITIATED 覆盖映射。
        """
        ordered = sorted(events, key=lambda e: (e.sim_time, e.timestamp))
        open_sid: Dict[Tuple[int, int], str] = {}

        def pair_key(ev: D2ZEvent) -> Optional[Tuple[int, int]]:
            if ev.uav_id is None or ev.uav_id < 0 or ev.zsp_id is None:
                return None
            return (ev.uav_id, int(ev.zsp_id))

        for e in ordered:
            pk = pair_key(e)
            if pk is None:
                continue
            if e.phase == D2ZPhase.INITIATED and e.auth_session_id:
                open_sid[pk] = e.auth_session_id
                continue
            if e.auth_session_id is None and pk in open_sid:
                e.auth_session_id = open_sid[pk]

    @staticmethod
    def parse_file(file_path: str) -> List[D2ZEvent]:
        """解析单个日志文件"""
        events: List[D2ZEvent] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    raw_data = D2ZLogParser.parse_log_line(line)
                    if raw_data is None:
                        continue
                    event = D2ZLogParser._extract_d2z_event(raw_data)
                    if event:
                        events.append(event)
        except OSError as e:
            print(f"[ERROR] Failed to read {file_path}: {e}")
        return events

    @staticmethod
    def parse_all_logs(log_dir: str) -> List[D2ZEvent]:
        """解析目录下所有 UAV/ZSP 日志"""
        all_events: List[D2ZEvent] = []
        log_pattern = os.path.join(log_dir, "sim_*_UAV_*.jsonl")
        log_files = glob.glob(log_pattern)
        zsp_pattern = os.path.join(log_dir, "sim_*_ZSP_*.jsonl")
        log_files.extend(glob.glob(zsp_pattern))
        print(f"[LOG_PARSER] Found {len(log_files)} log files in {log_dir}")
        for log_file in sorted(log_files):
            all_events.extend(D2ZLogParser.parse_file(log_file))
        all_events.sort(key=lambda e: (e.sim_time, e.timestamp))
        D2ZLogParser.enrich_auth_session_ids(all_events)
        return all_events
