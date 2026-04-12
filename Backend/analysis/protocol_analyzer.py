# Backend/analysis/protocol_analyzer.py
"""
D2Z协议效率分析器（支持 auth_session_id 与多轮会话）
"""

import statistics
from collections import defaultdict
from typing import Any, Dict, List, Optional

from core.event_models import D2ZEvent, D2ZMetrics, D2ZPhase, D2ZSession


class D2ZAnalyzer:
    """D2Z流程分析器"""

    def __init__(self, events: List[D2ZEvent]):
        self.events = events
        self.sessions: Dict[str, D2ZSession] = {}
        self.metrics = D2ZMetrics()
        self._analyze()

    def _analyze(self) -> None:
        self._identify_sessions()
        self._aggregate_session_events()
        self._calculate_metrics()

    def _identify_sessions(self) -> None:
        ordered = sorted(self.events, key=lambda e: (e.sim_time, e.timestamp))
        pending: Dict[str, D2ZSession] = {}
        stacks: Dict[tuple, List[str]] = defaultdict(list)

        for e in ordered:
            pair = None
            if e.uav_id is not None and e.uav_id >= 0 and e.zsp_id is not None:
                pair = (e.uav_id, int(e.zsp_id))

            if e.phase == D2ZPhase.INITIATED and pair is not None:
                sid = e.auth_session_id or f"legacy-{pair[0]}-{pair[1]}-{e.sim_time:.6f}"
                sess = D2ZSession(
                    uav_id=pair[0],
                    zsp_id=pair[1],
                    start_time=e.sim_time,
                    end_time=None,
                    auth_session_id=sid,
                )
                pending[sid] = sess
                stacks[pair].append(sid)
                continue

            if e.phase in (D2ZPhase.SUCCESS, D2ZPhase.FAILED):
                sid = e.auth_session_id
                if not sid and pair is not None and stacks[pair]:
                    sid = stacks[pair][-1]
                # ZSP 侧失败（如 UNKNOWN_PID）常缺少 peer_uav_id，解析后 uav_id=-1，
                # 无法按 (uav,zsp) 匹配栈；按 zsp_id 将失败归到该塔上最近仍未闭合的会话。
                if (
                    not sid
                    and e.phase == D2ZPhase.FAILED
                    and e.zsp_id is not None
                ):
                    zid = int(e.zsp_id)
                    candidates = [
                        psid
                        for psid, sess in pending.items()
                        if sess.zsp_id == zid
                    ]
                    if candidates:
                        sid = max(candidates, key=lambda psid: pending[psid].start_time)
                if sid and sid in pending:
                    sess = pending.pop(sid)
                    sess.end_time = e.sim_time
                    sess.success = e.phase == D2ZPhase.SUCCESS
                    sess.error_reason = None if sess.success else (e.error_reason or "failed")
                    sess.session_key_hash = e.session_key_hash or sess.session_key_hash
                    self.sessions[sid] = sess
                    pkey = (sess.uav_id, sess.zsp_id)
                    if pkey in stacks and sid in stacks[pkey]:
                        stacks[pkey].remove(sid)

    def _event_in_session(self, e: D2ZEvent, s: D2ZSession) -> bool:
        if s.end_time is None:
            return False
        if e.sim_time < s.start_time or e.sim_time > s.end_time:
            return False
        if s.auth_session_id and e.auth_session_id:
            return e.auth_session_id == s.auth_session_id
        return e.uav_id == s.uav_id and e.zsp_id == s.zsp_id

    def _aggregate_session_events(self) -> None:
        for sid, session in self.sessions.items():
            for e in self.events:
                if not self._event_in_session(e, session):
                    continue
                session.total_events += 1

                if e.phase in (
                    D2ZPhase.M1_SENT,
                    D2ZPhase.M1_RECEIVED,
                    D2ZPhase.M2_SENT,
                    D2ZPhase.M2_RECEIVED,
                    D2ZPhase.M3_M4_SENT,
                ):
                    session.message_count += 1

                mt = e.message_type or ""
                ps = int(e.payload_size or 0)
                if mt == "M1" and ps:
                    session.m1_size = max(session.m1_size, ps)
                elif mt == "M2" and ps:
                    session.m2_size = max(session.m2_size, ps)
                elif mt in ("M3", "M4", "M3_M4", "M3_4") and ps:
                    session.m3_m4_size = max(session.m3_m4_size, ps)

    def _calculate_metrics(self) -> None:
        if not self.sessions:
            return

        self.metrics.total_sessions = len(self.sessions)
        successful = [s for s in self.sessions.values() if s.success]
        failed = [s for s in self.sessions.values() if not s.success]
        self.metrics.successful_sessions = len(successful)
        self.metrics.failed_sessions = len(failed)
        if self.metrics.total_sessions:
            self.metrics.success_rate = self.metrics.successful_sessions / self.metrics.total_sessions * 100

        self.metrics.total_messages = sum(s.message_count for s in self.sessions.values())

        per_session_bytes: List[int] = []
        if successful:
            sizes_flat: List[float] = []
            for s in successful:
                tb = s.total_bytes
                per_session_bytes.append(tb)
                if s.m1_size:
                    sizes_flat.append(float(s.m1_size))
                if s.m2_size:
                    sizes_flat.append(float(s.m2_size))
                if s.m3_m4_size:
                    sizes_flat.append(float(s.m3_m4_size))
            if sizes_flat:
                self.metrics.avg_message_size = statistics.mean(sizes_flat)
                self.metrics.total_bytes = int(sum(per_session_bytes))
            if per_session_bytes:
                self.metrics.avg_bytes_per_successful_session = statistics.mean(per_session_bytes)
                msgs = [s.message_count for s in successful if s.message_count]
                if msgs:
                    self.metrics.avg_messages_per_successful_session = statistics.mean(msgs)

        durations = [s.duration for s in successful if s.duration > 0]
        if durations:
            self.metrics.avg_duration = statistics.mean(durations)
            self.metrics.min_duration = min(durations)
            self.metrics.max_duration = max(durations)
        else:
            self.metrics.min_duration = 0.0

        self.metrics.error_count = len(failed)
        for e in self.events:
            if e.phase != D2ZPhase.FAILED:
                continue
            mt = (e.message_type or "").upper()
            step = (e.protocol_step or "").upper()
            if "M1" in mt or "M1" in step:
                self.metrics.m1_errors += 1
            elif "M2" in mt or "M2" in step:
                self.metrics.m2_errors += 1
            elif "M3" in mt or "M4" in mt or "M3_M4" in mt:
                self.metrics.m3_m4_errors += 1

    def get_summary(self) -> Dict[str, Any]:
        return self.metrics.to_dict()

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.sessions[session_id].to_dict() if session_id in self.sessions else None

    def get_all_sessions(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.sessions.values()]

    def get_session_timeline(
        self,
        uav_id: int,
        zsp_id: int,
        session_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        timeline: List[Dict[str, Any]] = []
        candidates = [s for s in self.sessions.values() if s.uav_id == uav_id and s.zsp_id == zsp_id]
        if session_id:
            candidates = [
                s
                for s in candidates
                if s.auth_session_id == session_id or s.to_dict().get("session_id") == session_id
            ]
        if not candidates:
            return []
        session = max(candidates, key=lambda s: s.end_time or s.start_time)
        for e in self.events:
            if self._event_in_session(e, session):
                timeline.append(e.to_dict())
        timeline.sort(key=lambda d: (d.get("sim_time", 0), d.get("timestamp", 0)))
        return timeline

    def get_uav_statistics(self, uav_id: int) -> Dict[str, Any]:
        uav_sessions = [s for s in self.sessions.values() if s.uav_id == uav_id]
        if not uav_sessions:
            return {"uav_id": uav_id, "total_sessions": 0}
        successful = [s for s in uav_sessions if s.success]
        return {
            "uav_id": uav_id,
            "total_sessions": len(uav_sessions),
            "successful_sessions": len(successful),
            "failed_sessions": len(uav_sessions) - len(successful),
            "success_rate_percent": round(len(successful) / len(uav_sessions) * 100, 2) if uav_sessions else 0,
            "zsps_connected_to": list({s.zsp_id for s in uav_sessions}),
        }
