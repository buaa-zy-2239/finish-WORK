# Backend/analysis/protocol_analyzer.py
"""
D2Z协议效率分析器
"""

import statistics
from typing import List, Dict, Any, Optional

from core.event_models import D2ZEvent, D2ZPhase, D2ZSession, D2ZMetrics

class D2ZAnalyzer:
    """D2Z流程分析器"""
    
    def __init__(self, events: List[D2ZEvent]):
        self.events = events
        self.sessions: Dict[tuple, D2ZSession] = {}
        self.metrics = D2ZMetrics()
        
        self._analyze()
    
    def _analyze(self):
        """执行完整分析"""
        self._identify_sessions()
        self._calculate_metrics()
    
    def _identify_sessions(self):
        """识别D2Z会话"""
        session_starts = {}
        
        for event in self.events:
            key = (event.uav_id, event.zsp_id)
            
            if event.phase == D2ZPhase.INITIATED:
                session_starts[key] = event
            
            elif event.phase in [D2ZPhase.SUCCESS, D2ZPhase.FAILED]:
                if key in session_starts:
                    start_event = session_starts[key]
                    
                    session = D2ZSession(
                        uav_id=event.uav_id,
                        zsp_id=event.zsp_id,
                        start_time=start_event.sim_time,
                        end_time=event.sim_time,
                        success=event.success,
                        error_reason=event.error_reason,
                        session_key_hash=event.session_key_hash,
                    )
                    
                    self.sessions[key] = session
                    del session_starts[key]
        
        for event in self.events:
            key = (event.uav_id, event.zsp_id)
            
            if key in self.sessions:
                session = self.sessions[key]
                
                if session.start_time <= event.sim_time <= session.end_time:
                    session.total_events += 1
                    
                    if event.message_type:
                        session.message_count += 1
                        
                        if event.message_type == "M1" and event.payload_size:
                            session.m1_size = event.payload_size
                        elif event.message_type == "M2" and event.payload_size:
                            session.m2_size = event.payload_size
                        elif event.message_type in ["M3", "M4"] and event.payload_size:
                            session.m3_m4_size += event.payload_size
    
    def _calculate_metrics(self):
        """计算指标"""
        if not self.sessions:
            return
        
        self.metrics.total_sessions = len(self.sessions)
        successful_sessions = [s for s in self.sessions.values() if s.success]
        self.metrics.successful_sessions = len(successful_sessions)
        self.metrics.failed_sessions = self.metrics.total_sessions - self.metrics.successful_sessions
        
        if self.metrics.total_sessions > 0:
            self.metrics.success_rate = (
                self.metrics.successful_sessions / self.metrics.total_sessions * 100
            )
        
        self.metrics.total_messages = sum(s.message_count for s in self.sessions.values())
        
        if successful_sessions:
            message_sizes = []
            for session in successful_sessions:
                if session.m1_size:
                    message_sizes.append(session.m1_size)
                if session.m2_size:
                    message_sizes.append(session.m2_size)
                if session.m3_m4_size:
                    message_sizes.append(session.m3_m4_size)
            
            if message_sizes:
                self.metrics.avg_message_size = statistics.mean(message_sizes)
                self.metrics.total_bytes = sum(message_sizes)
        
        durations = [s.duration for s in successful_sessions if s.duration > 0]
        if durations:
            self.metrics.avg_duration = statistics.mean(durations)
            self.metrics.min_duration = min(durations)
            self.metrics.max_duration = max(durations)
        
        failed_sessions = [s for s in self.sessions.values() if not s.success]
        self.metrics.error_count = len(failed_sessions)
    
    def get_summary(self) -> Dict[str, Any]:
        return self.metrics.to_dict()
    
    def get_session(self, uav_id: int, zsp_id: int) -> Optional[Dict[str, Any]]:
        key = (uav_id, zsp_id)
        if key in self.sessions:
            return self.sessions[key].to_dict()
        return None
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.sessions.values()]
    
    def get_session_timeline(self, uav_id: int, zsp_id: int) -> List[Dict[str, Any]]:
        key = (uav_id, zsp_id)
        if key not in self.sessions:
            return []
        
        session = self.sessions[key]
        timeline = []
        
        for event in self.events:
            if (event.uav_id == uav_id and event.zsp_id == zsp_id and
                session.start_time <= event.sim_time <= session.end_time):
                timeline.append(event.to_dict())
        
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
            "zsps_connected_to": list(set(s.zsp_id for s in uav_sessions)),
        }