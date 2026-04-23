# Backend/core/log_parser.py
"""
日志解析器 - D2Z 流程（支持 auth_session_id / 双向实体关联）
"""

import json
import glob
import os
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .event_models import D2ZEvent, D2ZPhase


class D2ZLogParser:
    """D2Z流程日志解析器"""

    D2Z_EVENT_TYPES = {
        "AUTHENTICATION_SUCCESS": "auth",
        "AUTHENTICATION_FAILED": "auth",
        "AUTHENTICATION_TIMEOUT": "auth",
        "MESSAGE_SENT": "message",
        "MESSAGE_RECEIVED": "message",
        "MESSAGE_ERROR": "error",
        "WARNING": "warning",
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
            # 尝试从details中获取peer_uav_id
            if pu is not None:
                try:
                    uav_id = int(pu)
                except (TypeError, ValueError):
                    uav_id = -1
            # 对于SESSION_ESTABLISHED事件，尝试从peer_id获取uav_id
            if uav_id < 0 and details.get("peer_id") is not None:
                try:
                    uav_id = int(details.get("peer_id"))
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
        current_session_id = details.get("current_session_id")
        subsession_id = details.get("subsession_id")
        zsp_session_id = details.get("zsp_session_id")
        flow = details.get("flow")
        protocol = details.get("protocol")
        analysis_family = details.get("analysis_family")
        protocol_step = details.get("protocol_step")
        distance_m = details.get("distance_m")
        rssi = details.get("rssi")
        link_zone = details.get("link_zone")
        block_reason = details.get("block_reason")
        is_timeout = False

        # 过滤掉UAV侧的会话密钥建立和认证成功事件（但保留initiated事件用于会话创建）
        if entity_type == "UAV" and (event_type == "SESSION_ESTABLISHED" or (event_type == "AUTHENTICATION_SUCCESS" and details.get("phase") == "success")):
            return None

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
            # Check for timeout semantics via protocol_step or error_reason
            if protocol_step and any(t in str(protocol_step).upper() for t in ["TIMEOUT", "D2Z_ACK_TIMEOUT", "RETRY_BUDGET_EXHAUSTED"]):
                phase = D2ZPhase.TIMEOUT
                is_timeout = True
                error_reason = "d2z_ack_timeout" if "TIMEOUT" in str(protocol_step).upper() else error_reason
            # Check for PID unknown or decrypt failed errors
            elif error_reason and any(err in str(error_reason).lower() for err in ["unknown_pid", "invalid_pid", "pid_mismatch"]):
                error_reason = "unknown_pid"
            elif error_reason and any(err in str(error_reason).lower() for err in ["decrypt", "decryption"]):
                error_reason = "decrypt_failed"
            # 检查protocol_step中的PID错误
            elif protocol_step and any(err in str(protocol_step).upper() for err in ["UNKNOWN_PID", "PID_MISMATCH"]):
                error_reason = "unknown_pid"
                phase = D2ZPhase.FAILED
            # 检查protocol_step中的解密错误
            elif protocol_step and any(err in str(protocol_step).upper() for err in ["DECRYPT"]):
                error_reason = "decrypt_failed"
                phase = D2ZPhase.FAILED

        elif event_type == "AUTHENTICATION_TIMEOUT":
            phase = D2ZPhase.TIMEOUT
            success = False
            is_timeout = True
            error_reason = details.get("error_reason") or details.get("error_message") or "d2z_ack_timeout"

        elif event_type == "MESSAGE_ERROR":
            phase = D2ZPhase.FAILED
            success = False
            message_type = details.get("message_type")
            payload_size = details.get("payload_size")
            error_reason = details.get("error_reason", "message_error")
            protocol_step = protocol_step or "MESSAGE_ERROR"
            if protocol_step and any(t in str(protocol_step).upper() for t in ["TIMEOUT", "D2Z_ACK_TIMEOUT"]):
                phase = D2ZPhase.TIMEOUT
                is_timeout = True

        elif event_type == "MESSAGE_SENT":
            message_type = details.get("message_type", "") or ""
            payload_size = int(details.get("payload_size", 0) or 0)
            if message_type == "M1":
                phase = D2ZPhase.M1_SENT
            elif message_type == "M2":
                phase = D2ZPhase.M2_SENT
            elif message_type in ("M3", "M4", "M3_M4", "M3_4"):
                phase = D2ZPhase.M3_M4_SENT
            elif message_type == "D2Z_ACK":
                phase = D2ZPhase.ACK_RECEIVED
            else:
                return None

        elif event_type == "MESSAGE_RECEIVED":
            message_type = details.get("message_type", "") or ""
            # 过滤掉M2接收消息
            if message_type == "M2":
                return None
            payload_size = int(details.get("payload_size", 0) or 0)
            if message_type == "M1":
                phase = D2ZPhase.M1_RECEIVED
            elif message_type in ("M3", "M4", "M3_M4", "M3_4"):
                phase = D2ZPhase.M3_M4_SENT
            elif message_type == "D2Z_ACK":
                phase = D2ZPhase.ACK_RECEIVED
            else:
                return None

        elif event_type == "SESSION_ESTABLISHED":
            phase = D2ZPhase.SESSION_KEY_ESTABLISHED
            session_key_hash = details.get("session_key_hash")

        elif event_type == "WARNING":
            # 处理警告事件，包括重试和超时相关的警告
            protocol_step = details.get("protocol_step") or ""
            if "D2Z_RETRY" in protocol_step and "D2Z_RETRY_BUDGET_EXHAUSTED" not in protocol_step:
                phase = D2ZPhase.INITIATED
                message_type = "RETRY"
            elif "D2Z_ACK_TIMEOUT" in protocol_step or "TIMEOUT" in protocol_step or "D2Z_RETRY_BUDGET_EXHAUSTED" in protocol_step:
                phase = D2ZPhase.TIMEOUT
                success = False
                is_timeout = True
                error_reason = details.get("warning_message") or "timeout"
            elif "D2Z_M1_DROPPED" in protocol_step or "M1_DROPPED" in protocol_step:
                phase = D2ZPhase.M1_SENT
                success = False
                message_type = "M1"
                error_reason = details.get("warning_message") or "M1 dropped"
            elif "D2Z_M3_M4_DROPPED" in protocol_step or "M3_M4_DROPPED" in protocol_step:
                phase = D2ZPhase.M3_M4_SENT
                success = False
                message_type = "M3_M4"
                error_reason = details.get("warning_message") or "M3_M4 dropped"
            else:
                # 其他警告事件，暂时忽略
                return None

        if phase is None:
            return None

        # 确定会话结果字段
        session_result = None
        if phase == D2ZPhase.SUCCESS:
            session_result = "success"
        elif phase == D2ZPhase.TIMEOUT:
            session_result = "timeout"
        elif phase == D2ZPhase.FAILED:
            # 检查错误原因，确定是PID不匹配还是解密失败
            if error_reason and any(err in str(error_reason).lower() for err in ["unknown_pid", "invalid_pid", "pid_mismatch"]):
                session_result = "failed"
            elif error_reason and any(err in str(error_reason).lower() for err in ["decrypt", "decryption"]):
                session_result = "failed"
            else:
                session_result = "failed"

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
            current_session_id=current_session_id,
            subsession_id=subsession_id,
            zsp_session_id=zsp_session_id,
            flow=flow,
            protocol=protocol,
            analysis_family=analysis_family,
            protocol_step=protocol_step,
            distance_m=float(distance_m) if distance_m is not None else None,
            rssi=float(rssi) if rssi is not None else None,
            link_zone=link_zone,
            block_reason=block_reason,
            is_timeout=is_timeout,
            entity_type=entity_type,
            session_result=session_result,
        )

    @staticmethod
    def enrich_auth_session_ids(events: List[D2ZEvent]) -> None:
        """
        将 UAV 在 INITIATED 中产生的 auth_session_id 关联到同一 (uav_id, zsp_id) 的后续事件
        （含 ZSP 侧日志）。使用栈结构管理多个进行中的会话，确保按时间顺序正确匹配。
        同时也将 subsession_id 关联到同一会话的所有事件。
        """
        ordered = sorted(events, key=lambda e: (e.sim_time, e.timestamp))
        pending_sessions: Dict[Tuple[int, int], List[Tuple[str, float]]] = defaultdict(list)
        # 用于存储每个会话的子会话ID映射
        subsession_map: Dict[Tuple[int, int], Dict[str, int]] = defaultdict(dict)
        # 用于存储每个会话的最近子会话ID
        recent_subsession: Dict[Tuple[int, int, str], int] = {}
        # 用于存储每个(uav_id, zsp_id)对的最近会话信息
        recent_session: Dict[Tuple[int, int], Tuple[str, float]] = {}

        # 用于存储每个会话的子会话ID历史，按时间顺序
        subsession_history: Dict[Tuple[int, int, str], List[Tuple[int, float]]] = defaultdict(list)
        # 用于存储每个子会话的时间范围
        subsession_time_ranges: Dict[Tuple[int, int, str, int], Tuple[float, float]] = {}
        # 用于跟踪每个会话的M3/M4丢包事件
        m3m4_dropped_events: Dict[Tuple[int, int, str], List[float]] = defaultdict(list)
        # 用于存储每个ZSP事件的原始peer_uav_id，确保事件关联到正确的UAV
        zsp_peer_uav_map: Dict[int, Dict[float, int]] = defaultdict(dict)

        # 第一遍遍历：收集所有UAV侧的事件，包括M3/M4丢包事件，以及ZSP侧事件的原始peer_uav_id
        for e in ordered:
            if e.entity_type == "UAV" and e.auth_session_id:
                if e.uav_id >= 0 and e.zsp_id is not None:
                    session_key = (e.uav_id, int(e.zsp_id), e.auth_session_id)
                    # 记录M3/M4丢包事件
                    if e.phase == D2ZPhase.M3_M4_SENT and e.protocol_step and 'DROPPED' in e.protocol_step:
                        m3m4_dropped_events[session_key].append(e.sim_time)
                    # 存储子会话ID历史（如果有的话）
                    if e.subsession_id is not None:
                        subsession_history[session_key].append((e.subsession_id, e.sim_time))
            elif e.entity_type == "ZSP" and e.zsp_id is not None and e.uav_id >= 0:
                # 存储ZSP侧事件的原始peer_uav_id，确保事件关联到正确的UAV
                zsp_peer_uav_map[e.zsp_id][e.sim_time] = e.uav_id

        # 第二遍遍历：处理所有事件，关联会话ID和子会话ID
        for e in ordered:
            if e.entity_type == "UAV" and e.auth_session_id:
                if e.uav_id >= 0 and e.zsp_id is not None:
                    pk = (e.uav_id, int(e.zsp_id))
                    session_key = (e.uav_id, int(e.zsp_id), e.auth_session_id)
                    # 存储子会话ID
                    if e.subsession_id is not None:
                        subsession_map[pk][e.auth_session_id] = e.subsession_id
                        recent_subsession[session_key] = e.subsession_id
                        # 更新子会话的时间范围
                        subsession_key_tuple = (e.uav_id, int(e.zsp_id), e.auth_session_id, e.subsession_id)
                        if subsession_key_tuple not in subsession_time_ranges:
                            subsession_time_ranges[subsession_key_tuple] = (e.sim_time, e.sim_time)
                        else:
                            start_time, end_time = subsession_time_ranges[subsession_key_tuple]
                            subsession_time_ranges[subsession_key_tuple] = (min(start_time, e.sim_time), max(end_time, e.sim_time))
                    # 如果是INITIATED事件，添加到待处理会话
                    if e.phase == D2ZPhase.INITIATED:
                        pending_sessions[pk].append((e.auth_session_id, e.sim_time))
                        recent_session[pk] = (e.auth_session_id, e.sim_time)

            elif e.entity_type == "ZSP" and e.zsp_id is not None and e.uav_id >= 0:
                if e.auth_session_id:
                    continue
                # 使用原始的uav_id，确保事件关联到正确的UAV
                original_uav_id = e.uav_id
                pk = (original_uav_id, int(e.zsp_id))
                # 找到最接近但不晚于当前事件时间的会话ID
                candidates = [(sid, start_t) for sid, start_t in pending_sessions[pk]
                             if e.sim_time >= start_t]
                best_sid = None
                if candidates:
                    # 选择最近的会话ID（即开始时间最大的）
                    best_sid, _ = max(candidates, key=lambda x: x[1])
                elif pk in recent_session:
                    best_sid, _ = recent_session[pk]
                
                if best_sid:
                    e.auth_session_id = best_sid
                    session_key = (original_uav_id, int(e.zsp_id), best_sid)
                    # 找到最适合的子会话ID
                    best_subsid = None
                    
                    # 首先检查是否有M3/M4丢包事件
                    if session_key in m3m4_dropped_events:
                        # 找到所有发生在当前事件时间之前或同时的M3/M4丢包事件
                        for drop_time in m3m4_dropped_events[session_key]:
                            if drop_time <= e.sim_time:
                                # 检查事件类型，如果是ZSP侧的M3/M4接收、会话密钥建立或认证成功事件，关联到原来的子会话
                                # 因为这些事件表示M3/M4最终成功发送并被接收，应该属于原来的子会话
                                if e.phase in [D2ZPhase.M3_M4_SENT, D2ZPhase.SESSION_KEY_ESTABLISHED, D2ZPhase.SUCCESS] or \
                                   (e.protocol_step and ('M3_M4_RECV' in e.protocol_step or 'SESSION_KEY' in e.protocol_step or 'SUCCESS' in e.protocol_step)):
                                    # 找到M3/M4丢包事件对应的子会话ID
                                    latest_subsession = -1
                                    for subsession_id, event_time in subsession_history[session_key]:
                                        if event_time <= drop_time:
                                            latest_subsession = max(latest_subsession, subsession_id)
                                    # 选择M3/M4丢包事件对应的子会话ID，而不是新的子会话
                                    best_subsid = latest_subsession
                                    break
                    
                    # 如果没有找到，使用时间范围匹配
                    if best_subsid is None:
                        best_match = float('inf')
                        # 遍历所有子会话，找到时间范围包含当前事件时间的子会话
                        for (uav_id, zsp_id, session_id, subsession_id), (start_time, end_time) in subsession_time_ranges.items():
                            if uav_id == original_uav_id and zsp_id == int(e.zsp_id) and session_id == best_sid:
                                # 计算事件时间与子会话时间范围的距离
                                if start_time <= e.sim_time <= end_time:
                                    # 事件时间在子会话时间范围内，直接匹配
                                    best_subsid = subsession_id
                                    break
                                elif e.sim_time < start_time:
                                    # 事件时间在子会话开始之前，计算距离
                                    distance = start_time - e.sim_time
                                    if distance < best_match:
                                        best_match = distance
                                        best_subsid = subsession_id
                                elif e.sim_time > end_time:
                                    # 事件时间在子会话结束之后，计算距离
                                    distance = e.sim_time - end_time
                                    if distance < best_match:
                                        best_match = distance
                                        best_subsid = subsession_id
                    
                    # 直接使用事件的子会话ID，不根据M3/M4丢包事件调整
                    # 这样，每个子会话都会以M1开始，符合要求
                    
                    if best_subsid is not None:
                        e.subsession_id = best_subsid
                    elif best_sid in subsession_map[pk]:
                        e.subsession_id = subsession_map[pk][best_sid]
                    elif session_key in recent_subsession:
                        e.subsession_id = recent_subsession[session_key]

            # 为UAV侧的其他事件关联子会话ID
            elif e.entity_type == "UAV" and e.uav_id >= 0 and e.zsp_id is not None:
                pk = (e.uav_id, int(e.zsp_id))
                # 如果事件有auth_session_id，直接使用
                if e.auth_session_id:
                    session_key = (e.uav_id, int(e.zsp_id), e.auth_session_id)
                    # 如果事件没有子会话ID，尝试从映射中获取
                    if e.subsession_id is None:
                        if e.auth_session_id in subsession_map[pk]:
                            e.subsession_id = subsession_map[pk][e.auth_session_id]
                        elif session_key in recent_subsession:
                            e.subsession_id = recent_subsession[session_key]
                    
                    # 对于UAV侧的M2接收事件，如果发生在M3/M4丢包之后，也应该关联到新的子会话
                    if session_key in m3m4_dropped_events:
                        for drop_time in m3m4_dropped_events[session_key]:
                            if drop_time <= e.sim_time and (e.phase == D2ZPhase.M2_RECEIVED or e.protocol_step and 'M2_RECV' in e.protocol_step):
                                latest_subsession = -1
                                for subsession_id, event_time in subsession_history[session_key]:
                                    if event_time <= drop_time:
                                        latest_subsession = max(latest_subsession, subsession_id)
                                e.subsession_id = latest_subsession + 1
                                break
                # 如果事件没有auth_session_id但有zsp_session_id，尝试从最近的会话获取
                elif e.zsp_session_id and pk in recent_session:
                    best_sid, _ = recent_session[pk]
                    e.auth_session_id = best_sid
                    if best_sid in subsession_map[pk]:
                        e.subsession_id = subsession_map[pk][best_sid]
                    elif (e.uav_id, int(e.zsp_id), best_sid) in recent_subsession:
                        e.subsession_id = recent_subsession[(e.uav_id, int(e.zsp_id), best_sid)]

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
