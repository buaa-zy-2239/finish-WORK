"""
会话跟踪器模块 - 管理认证会话的时序记录和指标统计
"""

import json
import os
from collections import defaultdict
from typing import Optional, Dict, Any, List
from datetime import datetime

from .session_record import SessionRecord
from .metrics_collector import MetricsCollector


class SessionTracker:
    """会话跟踪器 - 负责会话时序记录和指标统计"""

    class ProtocolState:
        INIT = "INIT"
        M1_SEND = "M1_SEND"
        M1_RECEIVE = "M1_RECEIVE"
        M2_SEND = "M2_SEND"
        M2_RECEIVE = "M2_RECEIVE"
        M3_M4_SEND = "M3_M4_SEND"
        M3_M4_RECEIVE = "M3_M4_RECEIVE"
        ACK_SEND = "ACK_SEND"
        ACK_RECEIVE = "ACK_RECEIVE"
        SUCCESS = "SUCCESS"
        FAILED_MAC = "FAILED_MAC"
        FAILED_PID = "FAILED_PID"
        FAILED_NONCE = "FAILED_NONCE"
        FAILED_CRP = "FAILED_CRP"

    def __init__(self, sim_id: int, log_dir: str):
        self.sim_id = sim_id
        self.log_dir = log_dir

        self.sessions: Dict[str, SessionRecord] = {}
        self.sessions_by_pair: Dict[tuple, List[str]] = defaultdict(list)
        self.active_sessions: Dict[str, SessionRecord] = {}

        self.metrics = MetricsCollector()

        self.all_events: List[Dict[str, Any]] = []
        self.sid_alias: Dict[str, str] = {}
        self.session_counters: Dict[tuple, int] = defaultdict(int)
        self.subsession_counters: Dict[tuple, int] = defaultdict(int)
        self._retryable_sessions: Dict[tuple, int] = {}

        self.pid_to_uav_zsp: Dict[str, tuple] = {}
        self.uav_zsp_to_pids: Dict[tuple, List[str]] = defaultdict(list)

    def _get_session_key(self, auth_session_id: str) -> str:
        return self.sid_alias.get(auth_session_id, auth_session_id)

    def _classify_trigger(self, protocol_step: Optional[str]) -> str:
        step = (protocol_step or "").upper()
        if step == "D2Z_TRIGGER_EDGE_RSSI":
            return "edge_rssi"
        if step == "D2Z_TRIGGER_TIME":
            return "time_window"
        if step == "D2Z_INITIATED":
            return "connect"
        if "RETRY" in step:
            return "retry"
        if step.startswith("D2Z_TRIGGER_"):
            return step.replace("D2Z_TRIGGER_", "").lower()
        return "unknown"

    def register_pid(self, pid: str, uav_id: int, zsp_id: int) -> None:
        self.pid_to_uav_zsp[pid] = (uav_id, zsp_id)
        pair_key = (uav_id, zsp_id)
        if pid not in self.uav_zsp_to_pids[pair_key]:
            self.uav_zsp_to_pids[pair_key].append(pid)

    def resolve_pid(self, pid: str) -> Optional[tuple]:
        return self.pid_to_uav_zsp.get(pid)

    def resolve_session_by_pid(self, pid: str) -> Optional[SessionRecord]:
        result = self.resolve_pid(pid)
        if result is None:
            return None
        uav_id, zsp_id = result
        return self.get_session_by_pair(uav_id, zsp_id)

    def update_pid_mapping(self, old_pid: str, new_pid: str, uav_id: int, zsp_id: int) -> None:
        if old_pid in self.pid_to_uav_zsp:
            del self.pid_to_uav_zsp[old_pid]
        self.register_pid(new_pid, uav_id, zsp_id)

    def update_protocol_state(self, auth_session_id: str, new_state: str,
                               sim_time: float, message_type: Optional[str] = None,
                               error_type: Optional[str] = None,
                               error_reason: Optional[str] = None) -> None:
        sid = self._get_session_key(auth_session_id)
        if sid not in self.sessions:
            return

        session = self.sessions[sid]
        old_state = session.protocol_state
        
        if old_state == new_state:
            return

        session.protocol_state = new_state

        state_event = {
            "sim_time": sim_time,
            "old_state": old_state,
            "new_state": new_state,
            "message_type": message_type,
            "error_type": error_type,
            "error_reason": error_reason,
        }
        session.protocol_states.append(state_event)

        self._record_event({
            "sim_time": sim_time,
            "auth_session_id": auth_session_id,
            "phase": "protocol_state_change",
            "old_state": old_state,
            "new_state": new_state,
            "message_type": message_type,
            "error_type": error_type,
            "error_reason": error_reason,
        })

    def get_protocol_timeline(self, auth_session_id: str) -> List[Dict[str, Any]]:
        sid = self._get_session_key(auth_session_id)
        if sid not in self.sessions:
            return []
        return self.sessions[sid].protocol_states

    def get_session_summary(self, auth_session_id: str) -> Dict[str, Any]:
        sid = self._get_session_key(auth_session_id)
        if sid not in self.sessions:
            return {}
        session = self.sessions[sid]
        return {
            "uav_id": session.uav_id,
            "zsp_id": session.zsp_id,
            "auth_session_id": session.auth_session_id,
            "protocol_state": session.protocol_state,
            "session_result": session.session_result,
            "error_reason": session.error_reason,
            "subsession_id": session.current_subsession_id,
        }

    def generate_timeline_diagram(self, auth_session_id: str) -> Dict[str, Any]:
        sid = self._get_session_key(auth_session_id)
        if sid not in self.sessions:
            return {"error": "session not found"}

        session = self.sessions[sid]
        states = session.protocol_states

        timeline = {
            "uav_id": session.uav_id,
            "zsp_id": session.zsp_id,
            "session_id": auth_session_id,
            "final_state": session.protocol_state,
            "result": session.session_result,
            "error_reason": session.error_reason,
            "steps": [],
        }

        time_to_steps = {}
        
        for state_event in states:
            sim_time = state_event.get("sim_time")
            new_state = state_event.get("new_state")
            
            diagram = None
            if new_state == self.ProtocolState.FAILED_MAC:
                diagram = "M3/M4 -X (MAC verification failed)"
            elif new_state == self.ProtocolState.FAILED_PID:
                diagram = "M1/M2 -X (PID mismatch)"
            elif new_state == self.ProtocolState.FAILED_NONCE:
                diagram = "M2 -X (Nonce mismatch)"
            elif new_state == self.ProtocolState.FAILED_CRP:
                diagram = "M1/M2 -X (CRP decryption failed)"
            elif new_state == self.ProtocolState.SUCCESS:
                diagram = "M1 -> M2 -> M3/M4 (Success)"
            elif new_state == self.ProtocolState.M1_SEND:
                diagram = "UAV -> ZSP: M1"
            elif new_state == self.ProtocolState.M1_RECEIVE:
                diagram = "ZSP received M1"
            elif new_state == self.ProtocolState.M2_SEND:
                diagram = "ZSP -> UAV: M2"
            elif new_state == self.ProtocolState.M2_RECEIVE:
                diagram = "UAV received M2"
            elif new_state == self.ProtocolState.M3_M4_SEND:
                diagram = "UAV -> ZSP: M3/M4"
            elif new_state == self.ProtocolState.M3_M4_RECEIVE:
                diagram = "ZSP received M3/M4"
            elif new_state == self.ProtocolState.ACK_SEND:
                diagram = "ZSP -> UAV: ACK"
            elif new_state == self.ProtocolState.ACK_RECEIVE:
                diagram = "UAV received ACK"

            if diagram:
                step_info = {
                    "sim_time": sim_time,
                    "from": state_event.get("old_state"),
                    "to": new_state,
                    "diagram": diagram,
                }
                
                if sim_time not in time_to_steps:
                    time_to_steps[sim_time] = []
                time_to_steps[sim_time].append(step_info)

        for sim_time in sorted(time_to_steps.keys()):
            steps_at_time = time_to_steps[sim_time]
            
            if len(steps_at_time) == 1:
                timeline["steps"].append(steps_at_time[0])
            else:
                seen_diagrams = set()
                unique_steps = []
                for step in steps_at_time:
                    diagram = step["diagram"]
                    if diagram not in seen_diagrams:
                        seen_diagrams.add(diagram)
                        unique_steps.append(step)
                
                timeline["steps"].extend(unique_steps)

        if session.session_result == "timeout" and session.error_reason:
            last_state = session.protocol_state
            
            if last_state is None and session.protocol_states:
                last_state = session.protocol_states[-1].get("new_state", "INIT")
            
            success_states = {
                self.ProtocolState.SUCCESS,
                self.ProtocolState.ACK_RECEIVE,
            }
            
            if last_state in success_states:
                return timeline

            lost_packet = None
            next_expected = None

            if last_state == self.ProtocolState.INIT:
                lost_packet = "M1"
                next_expected = "M1"
            elif last_state == self.ProtocolState.M1_SEND:
                lost_packet = "M1"
                next_expected = "M2"
            elif last_state == self.ProtocolState.M1_RECEIVE:
                lost_packet = "M2"
                next_expected = "M2"
            elif last_state == self.ProtocolState.M2_SEND:
                lost_packet = "M2"
                next_expected = "M3/M4"
            elif last_state == self.ProtocolState.M2_RECEIVE:
                lost_packet = "M3/M4"
                next_expected = "M3/M4"
            elif last_state == self.ProtocolState.M3_M4_SEND:
                lost_packet = "M3/M4"
                next_expected = "ACK"
            elif last_state == self.ProtocolState.M3_M4_RECEIVE:
                lost_packet = "ACK"
                next_expected = "ACK"
            elif last_state == self.ProtocolState.ACK_SEND:
                lost_packet = "ACK"
                next_expected = "SUCCESS"
            elif last_state == self.ProtocolState.ACK_RECEIVE:
                return timeline
            else:
                lost_packet = "Unknown"
                next_expected = "Unknown"

            timeout_step = {
                "sim_time": session.end_time if session.end_time else session.start_time + 0.1,
                "from": last_state,
                "to": "TIMEOUT",
                "diagram": f"{lost_packet} -X (Timeout: {lost_packet} lost)",
                "error_reason": session.error_reason,
            }
            timeline["steps"].append(timeout_step)

        return timeline

    def start_session(self, uav_id: int, zsp_id: int, auth_session_id: str,
                     sim_time: float, protocol: str = "PMAP", analysis_family: str = "D2Z",
                     trigger_step: Optional[str] = None, distance_m: Optional[float] = None,
                     rssi: Optional[float] = None, link_zone: Optional[str] = None) -> None:
        existing_sid = self._get_session_key(auth_session_id)
        if existing_sid in self.active_sessions:
            existing = self.active_sessions[existing_sid]
            existing.current_subsession_id += 1
            existing.retry_count += 1
            existing.trigger_reason = self._classify_trigger(trigger_step)

            self._record_event({
                "sim_time": sim_time,
                "uav_id": uav_id,
                "zsp_id": zsp_id,
                "auth_session_id": auth_session_id,
                "subsession_id": existing.current_subsession_id,
                "phase": "initiated",
                "protocol": protocol,
                "analysis_family": analysis_family,
                "protocol_step": trigger_step,
                "trigger_reason": "retry",
                "distance_m": distance_m,
                "rssi": rssi,
                "link_zone": link_zone,
            })
            return

        session = SessionRecord(uav_id, zsp_id, auth_session_id)
        session.start_time = sim_time
        session.protocol = protocol
        session.analysis_family = analysis_family
        session.trigger_step = trigger_step
        session.trigger_reason = self._classify_trigger(trigger_step)
        session.init_distance_m = distance_m
        session.init_rssi = rssi
        session.init_link_zone = link_zone

        self.sessions[auth_session_id] = session
        self.active_sessions[auth_session_id] = session
        self.sessions_by_pair[(uav_id, zsp_id)].append(auth_session_id)

        self.metrics.trigger_breakdown[session.trigger_reason] += 1

        self._record_event({
            "sim_time": sim_time,
            "uav_id": uav_id,
            "zsp_id": zsp_id,
            "auth_session_id": auth_session_id,
            "subsession_id": 0,
            "phase": "initiated",
            "protocol": protocol,
            "analysis_family": analysis_family,
            "protocol_step": trigger_step,
            "trigger_reason": session.trigger_reason,
            "distance_m": distance_m,
            "rssi": rssi,
            "link_zone": link_zone,
        })

    def end_session(self, auth_session_id: str, sim_time: float, success: bool,
                   error_reason: Optional[str] = None, is_timeout: bool = False) -> None:
        sid = self._get_session_key(auth_session_id)

        if sid not in self.active_sessions:
            return

        session = self.active_sessions[sid]

        if not success and error_reason == "simulation_ended" and session.current_subsession_id < 2:
            parts = sid.split('_')
            if len(parts) >= 5:
                base_session_id = int(parts[3])
                self._retryable_sessions[(session.uav_id, session.zsp_id)] = base_session_id

        session.end_time = sim_time
        session.success = success
        session.error_reason = error_reason
        session.is_timeout = is_timeout
        session.session_result = "success" if success else ("timeout" if is_timeout else "failed")

        session.subsession_states[session.current_subsession_id] = session.session_result

        del self.active_sessions[sid]

        self._record_event({
            "sim_time": sim_time,
            "uav_id": session.uav_id,
            "zsp_id": session.zsp_id,
            "auth_session_id": auth_session_id,
            "subsession_id": session.current_subsession_id,
            "phase": session.session_result,
            "success": success,
            "error_reason": error_reason,
            "is_timeout": is_timeout,
        })

    def record_message(self, auth_session_id: str, message_type: str, payload_size: int,
                      sim_time: float, direction: str = "send", entity_type: str = "UAV") -> None:
        sid = self._get_session_key(auth_session_id)

        if sid in self.sessions:
            session = self.sessions[sid]
            session.message_count += 1
            session.total_bytes += payload_size

            if message_type == "M1":
                session.m1_size = max(session.m1_size, payload_size)
            elif message_type == "M2":
                session.m2_size = max(session.m2_size, payload_size)
            elif message_type in ("M3", "M4", "M3_M4", "M3_4"):
                session.m3_m4_size = max(session.m3_m4_size, payload_size)

        session_id = None
        subsession_id = None
        if sid in self.sessions:
            session = self.sessions[sid]
            subsession_id = session.current_subsession_id
            parts = session.auth_session_id.split('_')
            if len(parts) >= 5:
                session_id = int(parts[3])

        self._record_event({
            "sim_time": sim_time,
            "auth_session_id": auth_session_id,
            "session_id": session_id,
            "subsession_id": subsession_id,
            "message_type": message_type,
            "payload_size": payload_size,
            "direction": direction,
            "entity_type": entity_type,
            "phase": f"{message_type.lower()}_{direction}",
        })

    def record_session_key(self, auth_session_id: str, session_key_hash: str,
                          sim_time: float, entity_type: str = "UAV", zsp_session_id: Optional[str] = None) -> None:
        sid = self._get_session_key(auth_session_id)

        if sid in self.sessions:
            session = self.sessions[sid]
            if entity_type == "UAV":
                session.uav_session_key_hash = session_key_hash
            elif entity_type == "ZSP":
                session.zsp_session_key_hash = session_key_hash
                if zsp_session_id:
                    session.zsp_session_id = zsp_session_id

        self._record_event({
            "sim_time": sim_time,
            "auth_session_id": auth_session_id,
            "zsp_session_id": zsp_session_id,
            "session_key_hash": session_key_hash,
            "entity_type": entity_type,
            "phase": "session_key_established",
        })

    def record_error(self, auth_session_id: str, error_type: str, error_reason: str,
                    sim_time: float, message_type: Optional[str] = None) -> None:
        self.metrics.error_count += 1
        if message_type == "M1" or "M1" in error_type:
            self.metrics.m1_errors += 1
        elif message_type == "M2" or "M2" in error_type:
            self.metrics.m2_errors += 1
        elif message_type in ("M3", "M4", "M3_M4") or any(m in error_type for m in ("M3", "M4", "M3_M4")):
            self.metrics.m3_m4_errors += 1

        event = {
            "sim_time": sim_time,
            "error_type": error_type,
            "error_reason": error_reason,
            "phase": "failed",
            "success": False,
        }
        if auth_session_id:
            event["auth_session_id"] = auth_session_id
        if message_type:
            event["message_type"] = message_type

        self._record_event(event)

    def _record_event(self, event: Dict[str, Any]) -> None:
        event["timestamp"] = datetime.now().timestamp()
        self.all_events.append(event)

    def get_current_session_id(self, uav_id: int, zsp_id: int) -> int:
        return self.session_counters.get((uav_id, zsp_id), 0)

    def increment_session_id(self, uav_id: int, zsp_id: int) -> int:
        self.session_counters[(uav_id, zsp_id)] += 1
        return self.session_counters[(uav_id, zsp_id)]

    def get_current_subsession_id(self, uav_id: int, zsp_id: int, session_id: int) -> int:
        return self.subsession_counters.get((uav_id, zsp_id, session_id), 0)

    def increment_subsession_id(self, uav_id: int, zsp_id: int, session_id: int) -> int:
        self.subsession_counters[(uav_id, zsp_id, session_id)] += 1
        return self.subsession_counters[(uav_id, zsp_id, session_id)]

    def _generate_session_key(self, uav_id: int, zsp_id: int, session_id: int, subsession_id: int) -> str:
        return f"session_{uav_id}_{zsp_id}_{session_id}_{subsession_id}"

    def start_session_by_pair(self, uav_id: int, zsp_id: int,
                              sim_time: float, protocol: str = "PMAP",
                              analysis_family: str = "D2Z", trigger_step: Optional[str] = None,
                              distance_m: Optional[float] = None, rssi: Optional[float] = None,
                              link_zone: Optional[str] = None, is_retry: bool = False) -> str:
        current_session_id = self.get_current_session_id(uav_id, zsp_id)
        pair_key = (uav_id, zsp_id)
        reused_retryable_session = False

        if is_retry:
            if pair_key in self._retryable_sessions:
                session_id = self._retryable_sessions[pair_key]
                subsession_id = self.get_current_subsession_id(uav_id, zsp_id, session_id) + 1
                self.subsession_counters[(uav_id, zsp_id, session_id)] = subsession_id
                del self._retryable_sessions[pair_key]
                reused_retryable_session = True
            else:
                session_id = current_session_id - 1
                if session_id < 0:
                    session_id = 0
                subsession_id = self.increment_subsession_id(uav_id, zsp_id, session_id)
        else:
            if pair_key in self._retryable_sessions:
                session_id = self._retryable_sessions[pair_key]
                subsession_id = self.get_current_subsession_id(uav_id, zsp_id, session_id) + 1
                self.subsession_counters[(uav_id, zsp_id, session_id)] = subsession_id
                del self._retryable_sessions[pair_key]
                reused_retryable_session = True
            else:
                session_id = current_session_id
                subsession_id = self.get_current_subsession_id(uav_id, zsp_id, session_id)

        session_key = self._generate_session_key(uav_id, zsp_id, session_id, subsession_id)

        session = SessionRecord(uav_id, zsp_id, session_key)
        session.start_time = sim_time
        session.protocol = protocol
        session.analysis_family = analysis_family
        session.trigger_step = trigger_step
        session.trigger_reason = self._classify_trigger(trigger_step)
        session.init_distance_m = distance_m
        session.init_rssi = rssi
        session.init_link_zone = link_zone
        session.current_subsession_id = subsession_id

        if not is_retry and not reused_retryable_session:
            self.increment_session_id(uav_id, zsp_id)

        self.sessions[session_key] = session
        self.active_sessions[session_key] = session
        self.sessions_by_pair[(uav_id, zsp_id)].append(session_key)

        self.metrics.trigger_breakdown[session.trigger_reason] += 1

        self._record_event({
            "sim_time": sim_time,
            "uav_id": uav_id,
            "zsp_id": zsp_id,
            "auth_session_id": session_key,
            "session_id": session_id,
            "subsession_id": subsession_id,
            "phase": "initiated",
            "protocol": protocol,
            "analysis_family": analysis_family,
            "protocol_step": trigger_step,
            "trigger_reason": session.trigger_reason,
            "is_retry": is_retry,
            "distance_m": distance_m,
            "rssi": rssi,
            "link_zone": link_zone,
        })

        return session_key

    def get_session_by_pair(self, uav_id: int, zsp_id: int, session_id: Optional[int] = None) -> Optional[SessionRecord]:
        if session_id is None:
            session_id = self.get_current_session_id(uav_id, zsp_id)
            if session_id > 0:
                session_id -= 1

        subsession_id = self.get_current_subsession_id(uav_id, zsp_id, session_id)
        session_key = self._generate_session_key(uav_id, zsp_id, session_id, subsession_id)

        if session_key in self.active_sessions:
            return self.active_sessions[session_key]

        for i in range(subsession_id, -1, -1):
            session_key = self._generate_session_key(uav_id, zsp_id, session_id, i)
            if session_key in self.sessions:
                return self.sessions[session_key]

        return None

    def get_session_id_by_pair(self, uav_id: int, zsp_id: int, session_id: Optional[int] = None) -> Optional[str]:
        session = self.get_session_by_pair(uav_id, zsp_id, session_id)
        if session:
            return session.auth_session_id
        return None

    def calculate_metrics(self) -> MetricsCollector:
        self._calculate_auth_metrics()
        self._calculate_message_metrics()
        self._calculate_timing_metrics()
        self._calculate_recovery_metrics()
        return self.metrics

    def _calculate_auth_metrics(self) -> None:
        base_sessions: Dict[tuple, List] = defaultdict(list)

        for session in self.sessions.values():
            parts = session.auth_session_id.split('_')
            if len(parts) >= 5:
                uav_id = int(parts[1])
                zsp_id = int(parts[2])
                base_session_id = int(parts[3])
                key = (uav_id, zsp_id, base_session_id)
                base_sessions[key].append(session)

        successful_base = []
        failed_base = []
        timeout_base = []

        for key, subsessions in base_sessions.items():
            sorted_subsessions = sorted(subsessions, key=lambda s: s.current_subsession_id)
            last_subsession = sorted_subsessions[-1]

            if last_subsession.success:
                successful_base.append(last_subsession)
            elif last_subsession.is_timeout:
                timeout_base.append(last_subsession)
            elif last_subsession.success is False:
                failed_base.append(last_subsession)

        self.metrics.total_sessions = len(base_sessions)
        self.metrics.successful_sessions = len(successful_base)
        self.metrics.failed_sessions = len(failed_base)
        self.metrics.timeout_sessions = len(timeout_base)

    def _calculate_message_metrics(self) -> None:
        sizes = []
        per_session_bytes = []

        for session in self.sessions.values():
            if session.m1_size:
                sizes.append(session.m1_size)
            if session.m2_size:
                sizes.append(session.m2_size)
            if session.m3_m4_size:
                sizes.append(session.m3_m4_size)
            per_session_bytes.append(session.total_bytes)

        if sizes:
            self.metrics.avg_message_size = sum(sizes) / len(sizes)
        self.metrics.total_bytes = sum(per_session_bytes)

        successful = [s for s in self.sessions.values() if s.success]
        if successful:
            self.metrics.avg_bytes_per_successful_session = sum(s.total_bytes for s in successful) / len(successful)
            self.metrics.avg_messages_per_successful_session = sum(s.message_count for s in successful) / len(successful)

    def _calculate_timing_metrics(self) -> None:
        durations = [s.duration for s in self.sessions.values() if s.success and s.duration > 0]

        if durations:
            self.metrics.avg_duration = sum(durations) / len(durations)
            self.metrics.min_duration = min(durations)
            self.metrics.max_duration = max(durations)

    def _calculate_recovery_metrics(self) -> None:
        for pair, sess_ids in self.sessions_by_pair.items():
            sessions = sorted([self.sessions[sid] for sid in sess_ids], key=lambda s: s.start_time)
            failed_candidates = 0
            recovered = 0

            for idx, sess in enumerate(sessions):
                if sess.success or sess.is_timeout:
                    continue
                failed_candidates += 1
                if any(next_s.success for next_s in sessions[idx + 1:]):
                    recovered += 1

            if failed_candidates > 0:
                self.metrics.recovery_completion_ratio += recovered / failed_candidates

        if self.sessions_by_pair:
            self.metrics.recovery_completion_ratio /= len(self.sessions_by_pair)

    def get_all_sessions(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.sessions.values()]

    def get_session(self, auth_session_id: str) -> Optional[Dict[str, Any]]:
        sid = self._get_session_key(auth_session_id)
        session = self.sessions.get(sid)
        return session.to_dict() if session else None

    def get_session_timeline(self, uav_id: int, zsp_id: int, auth_session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        events = [e for e in self.all_events
                  if e.get("uav_id") == uav_id and e.get("zsp_id") == zsp_id]

        if auth_session_id:
            events = [e for e in events
                      if e.get("auth_session_id") == auth_session_id or
                         e.get("current_session_id") == auth_session_id]

        return sorted(events, key=lambda e: (e["sim_time"], e["timestamp"]))

    def get_metrics_summary(self) -> Dict[str, Any]:
        self.calculate_metrics()
        return self.metrics.to_dict()

    def export_results(self) -> Dict[str, Any]:
        self._close_pending_sessions()

        timeline_diagrams = {}
        for sid, session in self.sessions.items():
            timeline_diagrams[sid] = self.generate_timeline_diagram(sid)

        return {
            "sim_id": self.sim_id,
            "timestamp": datetime.now().isoformat(),
            "metrics": self.get_metrics_summary(),
            "sessions": self.get_all_sessions(),
            "events": self.all_events,
            "event_count": len(self.all_events),
            "timeline_diagrams": timeline_diagrams,
        }

    def _close_pending_sessions(self) -> None:
        active_session_ids = list(self.active_sessions.keys())

        for sid in active_session_ids:
            session = self.active_sessions.get(sid)
            if session and session.session_result == "pending":
                sim_time = session.start_time
                
                if session.protocol_states:
                    last_state_event = session.protocol_states[-1]
                    if "sim_time" in last_state_event:
                        sim_time = last_state_event["sim_time"]
                elif self.all_events:
                    last_event = self.all_events[-1]
                    if "sim_time" in last_event:
                        sim_time = last_event["sim_time"]

                if session.current_subsession_id is not None and session.current_subsession_id < 2:
                    parts = sid.split('_')
                    if len(parts) >= 5:
                        base_session_id = int(parts[3])
                        self._retryable_sessions[(session.uav_id, session.zsp_id)] = base_session_id

                protocol_state = getattr(session, 'protocol_state', None)
                success_states = {
                    self.ProtocolState.SUCCESS,
                    self.ProtocolState.ACK_RECEIVE,
                }
                if protocol_state in success_states:
                    self.end_session(
                        auth_session_id=sid,
                        sim_time=sim_time,
                        success=True,
                        error_reason=None,
                        is_timeout=False,
                    )
                else:
                    self.end_session(
                        auth_session_id=sid,
                        sim_time=sim_time,
                        success=False,
                        error_reason="simulation_ended",
                        is_timeout=True,
                    )

    def save_results(self, filename: Optional[str] = None) -> str:
        if not filename:
            filename = f"sim_{self.sim_id}_results.json"

        filepath = os.path.join(self.log_dir, filename)
        results = self.export_results()

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)

        return filepath