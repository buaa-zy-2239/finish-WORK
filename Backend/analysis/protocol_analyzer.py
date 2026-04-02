# Backend/analysis/protocol_analyzer.py
"""
D2Z协议效率分析器
"""

import statistics
from typing import List, Dict, Any, Optional
from collections import defaultdict

from ..core.event_models import D2ZEvent, D2ZPhase, D2ZSession, D2ZMetrics


class D2ZAnalyzer:
    """D2Z流程分析器"""
    
    def __init__(self, events: List[D2ZEvent]):
        """
        初始化分析器
        
        Args:
            events: D2Z事件列表
        """
        self.events = events
        self.sessions: Dict[tuple, D2ZSession] = {}  # (uav_id, zsp_id) -> D2ZSession
        self.metrics = D2ZMetrics()
        
        self._analyze()
    
    def _analyze(self):
        """执行完整分析"""
        # 1. 识别会话
        self._identify_sessions()
        
        # 2. 计算指标
        self._calculate_metrics()
    
    def _identify_sessions(self):
        """识别D2Z会话"""
        
        session_starts = {}  # (uav_id, zsp_id) -> start_event
        
        for event in self.events:
            key = (event.uav_id, event.zsp_id)
            
            # 会话开始
            if event.phase == D2ZPhase.INITIATED:
                session_starts[key] = event
            
            # 会话结束
            elif event.phase in [D2ZPhase.SUCCESS, D2ZPhase.FAILED]:
                if key in session_starts:
                    start_event = session_starts[key]
                    
                    # 创建会话
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
        
        # 关联事件到会话
        for event in self.events:
            key = (event.uav_id, event.zsp_id)
            
            if key in self.sessions:
                session = self.sessions[key]
                
                # 检查事件是否在会话时间范围内
                if session.start_time <= event.sim_time <= session.end_time:
                    session.total_events += 1
                    
                    # 统计消息
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
        
        # 认证统计
        self.metrics.total_sessions = len(self.sessions)
        successful_sessions = [s for s in self.sessions.values() if s.success]
        self.metrics.successful_sessions = len(successful_sessions)
        self.metrics.failed_sessions = self.metrics.total_sessions - self.metrics.successful_sessions
        
        if self.metrics.total_sessions > 0:
            self.metrics.success_rate = (
                self.metrics.successful_sessions / self.metrics.total_sessions * 100
            )
        
        # 消息统计
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
        
        # 时间统计
        durations = [s.duration for s in successful_sessions if s.duration > 0]
        if durations:
            self.metrics.avg_duration = statistics.mean(durations)
            self.metrics.min_duration = min(durations)
            self.metrics.max_duration = max(durations)
        
        # 错误统计
        failed_sessions = [s for s in self.sessions.values() if not s.success]
        self.metrics.error_count = len(failed_sessions)
    
    def get_summary(self) -> Dict[str, Any]:
        """获取分析摘要"""
        return self.metrics.to_dict()
    
    def get_session(self, uav_id: int, zsp_id: int) -> Optional[Dict[str, Any]]:
        """获取特定会话"""
        key = (uav_id, zsp_id)
        if key in self.sessions:
            return self.sessions[key].to_dict()
        return None
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """获取所有会话"""
        return [s.to_dict() for s in self.sessions.values()]
    
    def get_session_timeline(self, uav_id: int, zsp_id: int) -> List[Dict[str, Any]]:
        """获取会话的事件时间线"""
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
        """获取UAV的D2Z统计"""
        uav_sessions = [s for s in self.sessions.values() if s.uav_id == uav_id]
        
        if not uav_sessions:
            return {"uav_id": uav_id, "total_sessions": 0}
        
        successful = [s for s in uav_sessions if s.success]
        
        return {
            "uav_id": uav_id,
            "total_sessions": len(uav_sessions),
            "successful_sessions": len(successful),
            "failed_sessions": len(uav_sessions) - len(successful),
            "success_rate_percent": round(len(successful) / len(uav_sessions) * 100, 2),
            "zsps_connected_to": list(set(s.zsp_id for s in uav_sessions)),
        }