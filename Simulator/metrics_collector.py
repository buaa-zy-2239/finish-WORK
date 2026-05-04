"""
指标收集器模块 - 收集和计算认证协议性能指标
"""

from typing import Dict, Any, List
from collections import defaultdict


class MetricsCollector:
    """指标收集器"""

    def __init__(self):
        self.total_sessions: int = 0
        self.successful_sessions: int = 0
        self.failed_sessions: int = 0
        self.timeout_sessions: int = 0
        self.key_mismatch_sessions: int = 0

        self.total_messages: int = 0
        self.avg_message_size: float = 0.0
        self.total_bytes: int = 0
        self.avg_bytes_per_successful_session: float = 0.0
        self.avg_messages_per_successful_session: float = 0.0

        self.avg_duration: float = 0.0
        self.min_duration: float = 0.0
        self.max_duration: float = 0.0

        self.error_count: int = 0
        self.m1_errors: int = 0
        self.m2_errors: int = 0
        self.m3_m4_errors: int = 0

        self.trigger_breakdown: Dict[str, int] = defaultdict(int)

        self.success_vs_distance: List[Dict[str, Any]] = []

        self.recovery_completion_ratio: float = 0.0

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

        self.handover_count: int = 0
        self.handover_latency_avg_ms: float = 0.0
        self.handover_triggered_reauth_count: int = 0
        self.topology_change_rate: float = 0.0
        self.avg_link_lifetime_s: float = 0.0
        self.density_impact_score: float = 0.0

        self.mobility_metrics: Dict[str, Any] = {}

        self.subsession_metrics: Dict[str, Any] = {
            "avg_subsessions_per_session": 0.0,
            "subsession_success_rate": 0.0,
            "avg_subsession_duration_s": 0.0,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authentication": {
                "total_sessions": self.total_sessions,
                "successful": self.successful_sessions,
                "failed": self.failed_sessions,
                "timeout": self.timeout_sessions,
                "key_mismatch": self.key_mismatch_sessions,
                "success_rate_percent": (self.successful_sessions / self.total_sessions * 100) if self.total_sessions > 0 else 0.0,
            },
            "messaging": {
                "total_messages": self.total_messages,
                "avg_size_bytes": self.avg_message_size,
                "total_bytes": self.total_bytes,
                "avg_bytes_per_successful_session": self.avg_bytes_per_successful_session,
                "avg_messages_per_successful_session": self.avg_messages_per_successful_session,
            },
            "timing": {
                "avg_duration_seconds": self.avg_duration,
                "min_duration_seconds": self.min_duration,
                "max_duration_seconds": self.max_duration,
            },
            "errors": {
                "total": self.error_count,
                "M1_errors": self.m1_errors,
                "M2_errors": self.m2_errors,
                "M3_M4_errors": self.m3_m4_errors,
            },
            "triggers": {
                "breakdown": dict(self.trigger_breakdown),
            },
            "mechanism": {
                "recovery_completion_ratio": self.recovery_completion_ratio,
                "reauthentication_cost": self.reauthentication_cost,
                "success_vs_distance": self.success_vs_distance,
                "mobility_metrics": self.mobility_metrics,
                "subsession_metrics": self.subsession_metrics,
                "dropped_packets": {
                    "total": 0,
                    "M1": 0,
                    "M2": 0,
                    "M3_M4": 0,
                },
            },
        }