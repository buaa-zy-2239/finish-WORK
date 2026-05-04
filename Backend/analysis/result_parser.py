"""
直接解析Simulator生成的results.json文件的解析器
无需解析日志文件，直接从result文件获取会话和指标信息
"""

import json
import os
import statistics
from collections import defaultdict
from typing import Any, Dict, List, Optional


class ResultSession:
    """从result文件读取的会话信息"""
    
    def __init__(self, data: Dict[str, Any]):
        self.uav_id = data.get("uav_id")
        self.zsp_id = data.get("zsp_id")
        self.session_id = data.get("session_id")
        self.auth_session_id = data.get("auth_session_id")
        self.zsp_session_id = data.get("zsp_session_id")
        self.start_time = data.get("start_time")
        self.end_time = data.get("end_time")
        self.duration = data.get("duration_seconds", 0.0)
        self.success = data.get("success")
        self.is_timeout = data.get("is_timeout", False)
        self.error_reason = data.get("error_reason")
        self.session_result = data.get("session_result", "pending")
        self.subsession_states = data.get("subsession_states", {})
        self.message_count = data.get("message_count", 0)
        self.m1_size = data.get("m1_size", 0)
        self.m2_size = data.get("m2_size", 0)
        self.m3_m4_size = data.get("m3_m4_size", 0)
        self.total_bytes = data.get("total_bytes", 0)
        self.protocol = data.get("protocol")
        self.analysis_family = data.get("analysis_family")
        self.trigger_reason = data.get("trigger_reason")
        self.trigger_step = data.get("trigger_step")
        self.retry_count = data.get("retry_count", 0)
        self.init_distance_m = data.get("init_distance_m")
        self.init_rssi = data.get("init_rssi")
        self.init_link_zone = data.get("init_link_zone")
        self.uav_session_key_hash = None
        self.zsp_session_key_hash = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "uav_id": self.uav_id,
            "zsp_id": self.zsp_id,
            "session_id": self.session_id,
            "auth_session_id": self.auth_session_id,
            "zsp_session_id": self.zsp_session_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "duration_seconds": self.duration,
            "success": self.success,
            "is_timeout": self.is_timeout,
            "error_reason": self.error_reason,
            "session_result": self.session_result,
            "subsession_states": self.subsession_states,
            "message_count": self.message_count,
            "m1_size": self.m1_size,
            "m2_size": self.m2_size,
            "m3_m4_size": self.m3_m4_size,
            "total_bytes": self.total_bytes,
            "protocol": self.protocol,
            "analysis_family": self.analysis_family,
            "trigger_reason": self.trigger_reason,
            "trigger_step": self.trigger_step,
            "retry_count": self.retry_count,
            "init_distance_m": self.init_distance_m,
            "init_rssi": self.init_rssi,
            "init_link_zone": self.init_link_zone,
            "dropped_packets": {
                "M1": 0,
                "M2": 0,
                "M3_M4": 0,
                "total": 0,
            },
        }


class ResultMetrics:
    """从result文件读取的指标信息"""
    
    def __init__(self):
        # 认证统计
        self.total_sessions = 0
        self.successful_sessions = 0
        self.failed_sessions = 0
        self.timeout_sessions = 0
        self.key_mismatch_sessions = 0
        self.success_rate = 0.0
        self.session_completion_rate = 0.0
        self.protocol_success_rate = 0.0
        self.protocol_correctness_rate = 0.0
        self.channel_reliability = 0.0
        
        # 消息统计
        self.total_messages = 0
        self.avg_message_size = 0.0
        self.total_bytes = 0
        self.avg_bytes_per_successful_session = 0.0
        self.avg_messages_per_successful_session = 0.0
        
        # 时间统计
        self.avg_duration = 0.0
        self.min_duration = 0.0
        self.max_duration = 0.0
        
        # 错误统计
        self.error_count = 0
        self.m1_errors = 0
        self.m2_errors = 0
        self.m3_m4_errors = 0
        
        # 触发来源统计
        self.trigger_breakdown: Dict[str, int] = {}
        
        # 距离分桶统计
        self.success_vs_distance: List[Dict[str, Any]] = []
        
        # 恢复完成率
        self.recovery_completion_ratio = 0.0
        
        # 重认证成本
        self.reauthentication_cost: Dict[str, Any] = {
            "retry_successes": 0,
            "baseline_successes": 0,
            "avg_messages_retry_success": 0.0,
            "avg_bytes_retry_success": 0.0,
            "avg_duration_retry_success": 0.0,
            "extra_messages_vs_baseline": 0.0,
            "extra_bytes_vs_baseline": 0.0,
            "extra_duration_vs_baseline": 0.0,
        }
        
        # 可扩展性指标
        self.handover_count = 0
        self.handover_latency_avg_ms = 0.0
        self.handover_triggered_reauth_count = 0
        self.topology_change_rate = 0.0
        self.avg_link_lifetime_s = 0.0
        self.density_impact_score = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "authentication": {
                "total_sessions": self.total_sessions,
                "successful": self.successful_sessions,
                "failed": self.failed_sessions,
                "timeout": self.timeout_sessions,
                "key_mismatch": self.key_mismatch_sessions,
                "success_rate_percent": self.success_rate,
                "success_rate": self.success_rate,
                "session_completion_rate": self.session_completion_rate,
                "protocol_success_rate": self.protocol_success_rate,
                "protocol_correctness_rate": self.protocol_correctness_rate,
                "channel_reliability": self.channel_reliability,
            },
            "messaging": {
                "total_messages": self.total_messages,
                "avg_size_bytes": self.avg_message_size,
                "avg_message_size": self.avg_message_size,
                "total_bytes": self.total_bytes,
                "avg_bytes_per_successful_session": self.avg_bytes_per_successful_session,
                "avg_messages_per_successful_session": self.avg_messages_per_successful_session,
            },
            "timing": {
                "avg_duration_seconds": self.avg_duration,
                "avg_duration": self.avg_duration,
                "min_duration_seconds": self.min_duration,
                "min_duration": self.min_duration,
                "max_duration_seconds": self.max_duration,
                "max_duration": self.max_duration,
            },
            "errors": {
                "total": self.error_count,
                "M1_errors": self.m1_errors,
                "M2_errors": self.m2_errors,
                "M3_M4_errors": self.m3_m4_errors,
            },
            "triggers": {
                "breakdown": self.trigger_breakdown,
            },
            "mechanism": {
                "recovery_completion_ratio": self.recovery_completion_ratio,
                "reauthentication_cost": self.reauthentication_cost,
                "success_vs_distance": self.success_vs_distance,
                "dropped_packets": {
                    "M1": 0,
                    "M2": 0,
                    "M3_M4": 0,
                    "total": 0,
                },
                "dropped_packets_by_pair": {},
                "mobility_metrics": {
                    "avg_speed_mps": 0.0,
                    "max_speed_mps": 0.0,
                    "avg_acceleration_mps2": 0.0,
                    "topology_dynamicity": "unknown",
                    "expected_link_lifetime_s": 0.0,
                },
                "subsession_metrics": {
                    "avg_subsessions_per_session": 0.0,
                    "subsession_success_rate": 0.0,
                    "avg_subsession_duration_s": 0.0,
                },
            },
            "scalability": {
                "handover_count": self.handover_count,
                "handover_latency_avg_ms": self.handover_latency_avg_ms,
                "handover_triggered_reauth_count": self.handover_triggered_reauth_count,
                "topology_change_rate": self.topology_change_rate,
                "avg_link_lifetime_s": self.avg_link_lifetime_s,
                "density_impact_score": self.density_impact_score,
            },
        }


class ResultParser:
    """直接解析Simulator生成的results.json文件"""
    
    def __init__(self, result_file_path: str):
        self.result_file_path = result_file_path
        self.data: Dict[str, Any] = {}
        self.sessions: List[ResultSession] = []
        self.metrics = ResultMetrics()
        self.events: List[Dict[str, Any]] = []
        self.timeline_diagrams: Dict[str, Dict[str, Any]] = {}
        self._load_and_parse()
    
    def _load_and_parse(self) -> None:
        """加载并解析result文件"""
        if not os.path.exists(self.result_file_path):
            raise FileNotFoundError(f"Result file not found: {self.result_file_path}")
        
        with open(self.result_file_path, "r", encoding="utf-8") as f:
            self.data = json.load(f)
        
        # 解析会话
        self._parse_sessions()
        
        # 解析事件
        self._parse_events()
        
        # 解析时序图数据
        self._parse_timeline_diagrams()
        
        # 解析指标
        self._parse_metrics()
        
        # 补充计算额外指标
        self._calculate_additional_metrics()
    
    def _parse_sessions(self) -> None:
        """解析会话列表"""
        sessions_data = self.data.get("sessions", [])
        for sess_data in sessions_data:
            session = ResultSession(sess_data)
            self.sessions.append(session)
    
    def _parse_events(self) -> None:
        """解析事件列表"""
        self.events = self.data.get("events", [])
    
    def _parse_timeline_diagrams(self) -> None:
        """解析时序图数据"""
        self.timeline_diagrams = self.data.get("timeline_diagrams", {})
    
    def _parse_metrics(self) -> None:
        """解析指标数据"""
        metrics_data = self.data.get("metrics", {})
        
        # 认证统计
        auth = metrics_data.get("authentication", {})
        self.metrics.total_sessions = auth.get("total_sessions", 0)
        self.metrics.successful_sessions = auth.get("successful", 0)
        self.metrics.failed_sessions = auth.get("failed", 0)
        self.metrics.timeout_sessions = auth.get("timeout", 0)
        self.metrics.key_mismatch_sessions = auth.get("key_mismatch", 0)
        
        # 消息统计
        messaging = metrics_data.get("messaging", {})
        self.metrics.total_messages = messaging.get("total_messages", 0)
        self.metrics.avg_message_size = messaging.get("avg_size_bytes", 0.0)
        self.metrics.total_bytes = messaging.get("total_bytes", 0)
        self.metrics.avg_bytes_per_successful_session = messaging.get("avg_bytes_per_successful_session", 0.0)
        self.metrics.avg_messages_per_successful_session = messaging.get("avg_messages_per_successful_session", 0.0)
        
        # 时间统计
        timing = metrics_data.get("timing", {})
        self.metrics.avg_duration = timing.get("avg_duration_seconds", 0.0)
        self.metrics.min_duration = timing.get("min_duration_seconds", 0.0)
        self.metrics.max_duration = timing.get("max_duration_seconds", 0.0)
        
        # 错误统计
        errors = metrics_data.get("errors", {})
        self.metrics.error_count = errors.get("total", 0)
        self.metrics.m1_errors = errors.get("M1_errors", 0)
        self.metrics.m2_errors = errors.get("M2_errors", 0)
        self.metrics.m3_m4_errors = errors.get("M3_M4_errors", 0)
        
        # 触发来源统计
        triggers = metrics_data.get("triggers", {})
        self.metrics.trigger_breakdown = triggers.get("breakdown", {})
        
        # 机制相关指标
        mechanism = metrics_data.get("mechanism", {})
        self.metrics.recovery_completion_ratio = mechanism.get("recovery_completion_ratio", 0.0)
        self.metrics.reauthentication_cost = mechanism.get("reauthentication_cost", {})
        self.metrics.success_vs_distance = mechanism.get("success_vs_distance", [])
        
        # 计算成功率指标
        if self.metrics.total_sessions > 0:
            self.metrics.success_rate = (self.metrics.successful_sessions / self.metrics.total_sessions) * 100
            self.metrics.session_completion_rate = self.metrics.success_rate
            self.metrics.protocol_success_rate = self.metrics.success_rate
            self.metrics.protocol_correctness_rate = self.metrics.success_rate
            
            # 信道可靠性 = 有效会话数 / 总发起会话数
            total_initiated = len(self.sessions)
            self.metrics.channel_reliability = (self.metrics.total_sessions / total_initiated) * 100 if total_initiated > 0 else 0.0
        else:
            self.metrics.success_rate = 0.0
            self.metrics.session_completion_rate = 0.0
            self.metrics.protocol_success_rate = 0.0
            self.metrics.protocol_correctness_rate = 0.0
            self.metrics.channel_reliability = 0.0
    
    def _calculate_additional_metrics(self) -> None:
        """计算额外指标"""
        # 按UAV-ZSP对分组
        by_pair: Dict[tuple, List[ResultSession]] = defaultdict(list)
        for s in self.sessions:
            by_pair[(s.uav_id, s.zsp_id)].append(s)
        
        # 计算恢复完成率
        failed_candidates = 0
        recovered = 0
        for pair_sessions in by_pair.values():
            ordered_pair = sorted(pair_sessions, key=lambda s: s.start_time)
            for idx, sess in enumerate(ordered_pair):
                if sess.success or sess.is_timeout:
                    continue
                failed_candidates += 1
                if any(next_s.success for next_s in ordered_pair[idx + 1:]):
                    recovered += 1
        self.metrics.recovery_completion_ratio = recovered / failed_candidates if failed_candidates else 0.0
        
        # 计算可扩展性指标
        self._calculate_scalability_metrics()
    
    def _calculate_scalability_metrics(self) -> None:
        """计算可扩展性指标"""
        # 基于事件计算handover相关指标
        handover_events = [e for e in self.events if e.get("phase") == "handover" or e.get("protocol_step") == "HANDOVER"]
        self.metrics.handover_count = len(handover_events)
        
        # 估算拓扑变化率
        if self.sessions:
            sim_times = [e.get("sim_time") for e in self.events if e.get("sim_time") is not None]
            if sim_times:
                sim_duration_s = max(sim_times) - min(sim_times)
                if sim_duration_s > 0:
                    unique_uavs = len(set(s.uav_id for s in self.sessions if s.uav_id is not None))
                    if unique_uavs > 0:
                        self.metrics.topology_change_rate = self.metrics.handover_count / (sim_duration_s * unique_uavs)
        
        # 平均链路持续时间估算
        successful_durations = [s.duration for s in self.sessions if s.success and s.duration > 0]
        if successful_durations:
            avg_session_duration = statistics.mean(successful_durations)
            self.metrics.avg_link_lifetime_s = avg_session_duration * 2
        
        # 密度影响评分
        reliability = self.metrics.channel_reliability / 100.0
        self.metrics.density_impact_score = 1.0 - reliability
    
    def get_summary(self) -> Dict[str, Any]:
        """获取指标摘要"""
        return self.metrics.to_dict()
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """获取所有会话列表"""
        return [s.to_dict() for s in self.sessions]
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取单个会话"""
        for s in self.sessions:
            if s.session_id == session_id or s.auth_session_id == session_id:
                return s.to_dict()
        return None
    
    def get_session_timeline(self, uav_id: int, zsp_id: int, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取会话时序事件"""
        timeline = []
        
        relevant_events = []
        for e in self.events:
            # 如果提供了 session_id，优先使用 auth_session_id 来匹配
            if session_id:
                if e.get("auth_session_id") == session_id:
                    relevant_events.append(e)
            else:
                # 如果没有提供 session_id，使用 uav_id 和 zsp_id 来匹配
                event_uav_id = e.get("uav_id")
                event_zsp_id = e.get("zsp_id")
                # 处理 uav_id/zsp_id 为 None 的情况
                if (event_uav_id == uav_id or event_uav_id is None) and \
                   (event_zsp_id == zsp_id or event_zsp_id is None):
                    relevant_events.append(e)
        
        relevant_events.sort(key=lambda e: (e.get("sim_time", 0), e.get("timestamp", 0)))
        
        for e in relevant_events:
            timeline.append(e)
        
        return timeline
    
    def get_uav_statistics(self, uav_id: int) -> Dict[str, Any]:
        """获取UAV统计信息"""
        uav_sessions = [s for s in self.sessions if s.uav_id == uav_id]
        if not uav_sessions:
            return {"uav_id": uav_id, "total_sessions": 0}
        
        successful = [s for s in uav_sessions if s.success]
        return {
            "uav_id": uav_id,
            "total_sessions": len(uav_sessions),
            "successful_sessions": len(successful),
            "failed_sessions": len(uav_sessions) - len(successful),
            "success_rate_percent": round(len(successful) / len(uav_sessions) * 100, 2) if uav_sessions else 0,
            "zsps_connected_to": list({s.zsp_id for s in uav_sessions if s.zsp_id is not None}),
        }
    
    def get_timeline_diagram(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话的时序图数据"""
        return self.timeline_diagrams.get(session_id)
    
    def get_all_timeline_diagrams(self) -> Dict[str, Dict[str, Any]]:
        """获取所有会话的时序图数据"""
        return self.timeline_diagrams
    
    @staticmethod
    def parse_result_file(file_path: str) -> "ResultParser":
        """静态方法：解析result文件"""
        return ResultParser(file_path)