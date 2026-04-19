# Backend/core/event_models.py
"""
事件数据模型 - D2Z 流程与 API DTO
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class D2ZPhase(Enum):
    """D2Z认证阶段"""
    INITIATED = "initiated"
    M1_SENT = "M1_sent"
    M1_RECEIVED = "M1_received"
    M2_SENT = "M2_sent"
    M2_RECEIVED = "M2_received"
    M3_M4_SENT = "M3_M4_sent"
    SESSION_KEY_ESTABLISHED = "session_key_established"
    SUCCESS = "success"
    FAILED = "failed"          # explicit verification failure (MAC fail, key mismatch, PID invalid, decryption error)
    TIMEOUT = "timeout"        # due to packet loss, interception, d2z_ack_timeout - NOT counted as authentication failure


@dataclass
class D2ZEvent:
    """D2Z认证事件（已解析）"""
    timestamp: float
    sim_time: float
    uav_id: int
    zsp_id: Optional[int]
    phase: D2ZPhase
    message_type: Optional[str] = None
    payload_size: Optional[int] = None
    success: bool = True
    error_reason: Optional[str] = None
    session_key_hash: Optional[str] = None
    auth_session_id: Optional[str] = None
    flow: Optional[str] = None
    protocol: Optional[str] = None
    analysis_family: Optional[str] = None
    protocol_step: Optional[str] = None
    distance_m: Optional[float] = None
    rssi: Optional[float] = None
    entity_type: Optional[str] = None  # 原始实体类型 "UAV" 或 "ZSP"
    link_zone: Optional[str] = None
    block_reason: Optional[str] = None
    is_timeout: bool = False   # new field to distinguish timeout from explicit failure

    @property
    def datetime_str(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "sim_time": self.sim_time,
            "datetime": self.datetime_str,
            "uav_id": self.uav_id,
            "zsp_id": self.zsp_id,
            "phase": self.phase.value,
            "message_type": self.message_type,
            "payload_size": self.payload_size,
            "success": self.success,
            "error_reason": self.error_reason,
            "session_key_hash": self.session_key_hash,
            "auth_session_id": self.auth_session_id,
            "flow": self.flow,
            "protocol": self.protocol,
            "analysis_family": self.analysis_family,
            "protocol_step": self.protocol_step,
            "distance_m": self.distance_m,
            "rssi": self.rssi,
            "link_zone": self.link_zone,
            "block_reason": self.block_reason,
            "is_timeout": self.is_timeout,
        }


@dataclass
class D2ZSession:
    """D2Z会话信息"""
    uav_id: int
    zsp_id: int
    start_time: float
    end_time: Optional[float]
    auth_session_id: Optional[str] = None
    total_events: int = 0
    message_count: int = 0
    m1_size: int = 0
    m2_size: int = 0
    m3_m4_size: int = 0
    success: bool = False
    error_reason: Optional[str] = None
    session_key_hash: Optional[str] = None
    uav_session_key_hash: Optional[str] = None  # UAV视角的session key
    zsp_session_key_hash: Optional[str] = None  # ZSP视角的session key
    protocol: Optional[str] = None
    analysis_family: Optional[str] = None
    trigger_reason: Optional[str] = None
    trigger_step: Optional[str] = None
    init_distance_m: Optional[float] = None
    init_rssi: Optional[float] = None
    init_link_zone: Optional[str] = None
    is_timeout: bool = False

    @property
    def duration(self) -> float:
        if self.end_time is None:
            return 0.0
        return self.end_time - self.start_time

    @property
    def total_bytes(self) -> int:
        return int(self.m1_size or 0) + int(self.m2_size or 0) + int(self.m3_m4_size or 0)

    def to_dict(self) -> Dict[str, Any]:
        sid = self.auth_session_id or f"{self.uav_id}-{self.zsp_id}"
        return {
            "session_id": sid,
            "auth_session_id": self.auth_session_id,
            "uav_id": self.uav_id,
            "zsp_id": self.zsp_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration,
            "total_events": self.total_events,
            "message_count": self.message_count,
            "message_sizes": {
                "M1": self.m1_size,
                "M2": self.m2_size,
                "M3_M4": self.m3_m4_size,
            },
            "total_bytes": self.total_bytes,
            "bytes_per_message": round(self.total_bytes / self.message_count, 2) if self.message_count else 0.0,
            "success": self.success,
            "error_reason": self.error_reason,
            "session_key_hash": self.session_key_hash,
            "protocol": self.protocol,
            "analysis_family": self.analysis_family,
            "trigger_reason": self.trigger_reason,
            "trigger_step": self.trigger_step,
            "init_distance_m": self.init_distance_m,
            "init_rssi": self.init_rssi,
            "init_link_zone": self.init_link_zone,
            "is_timeout": self.is_timeout,
        }


@dataclass
class D2ZMetrics:
    """D2Z流程指标"""
    total_sessions: int = 0
    successful_sessions: int = 0
    failed_sessions: int = 0
    timeout_sessions: int = 0
    success_rate: float = 0.0  # overall success rate (end-to-end, includes channel impact)
    protocol_success_rate: float = 0.0  # pure protocol success rate (excludes timeouts)
    channel_reliability: float = 0.0  # proportion of sessions that complete protocol flow
    total_messages: int = 0
    avg_message_size: float = 0.0
    total_bytes: int = 0
    avg_duration: float = 0.0
    min_duration: float = 0.0
    max_duration: float = 0.0
    error_count: int = 0
    m1_errors: int = 0
    m2_errors: int = 0
    m3_m4_errors: int = 0
    avg_bytes_per_successful_session: float = 0.0
    avg_messages_per_successful_session: float = 0.0
    trigger_breakdown: Dict[str, int] = None
    success_vs_distance: List[Dict[str, Any]] = None
    recovery_completion_ratio: float = 0.0
    reauthentication_cost: Dict[str, Any] = None
    # 新增：学术严谨的指标命名
    session_completion_rate: float = 0.0  # 同success_rate，但命名更准确
    protocol_correctness_rate: float = 0.0  # 同protocol_success_rate，强调正确性
    key_mismatch_sessions: int = 0  # 双方session_key不匹配的"虚假成功"会话数

    # 新增：Scalability & Topology Dynamics 指标
    handover_count: int = 0  # ZSP切换次数
    handover_latency_avg_ms: float = 0.0  # 平均切换延迟
    handover_triggered_reauth_count: int = 0  # 切换触发的重认证次数
    topology_change_rate: float = 0.0  # 拓扑变化率 (links/s/UAV)
    avg_link_lifetime_s: float = 0.0  # 平均链路持续时间
    density_impact_score: float = 0.0  # 密度影响评分 (0-1)

    def __post_init__(self) -> None:
        if self.trigger_breakdown is None:
            self.trigger_breakdown = {}
        if self.success_vs_distance is None:
            self.success_vs_distance = []
        if self.reauthentication_cost is None:
            self.reauthentication_cost = {}

    def to_dict(self) -> Dict[str, Any]:
        min_d = self.min_duration if self.min_duration != float("inf") else 0.0
        # 学术严谨的指标说明
        # session_completion_rate: 端到端会话完成率（含调度/信道影响）
        # protocol_correctness_rate: 协议正确性（排除timeout，纯协议层面）
        return {
            "authentication": {
                "total_sessions": self.total_sessions,
                "successful": self.successful_sessions,
                "failed": self.failed_sessions,
                "timeout": self.timeout_sessions,
                "key_mismatch_sessions": self.key_mismatch_sessions,
                "success_rate_percent": round(self.success_rate, 2),
                "effective_success_rate": round(self.successful_sessions / self.total_sessions * 100 if self.total_sessions > 0 else 0, 2),
                "session_completion_rate": round(self.session_completion_rate, 2),
                "protocol_success_rate": round(self.protocol_success_rate, 2),
                "protocol_correctness_rate": round(self.protocol_correctness_rate, 2),
                "channel_reliability": round(self.channel_reliability, 2),
                "_metric_notes": {
                    "session_completion_rate": "End-to-end completion rate (includes scheduling/channel impact)",
                    "protocol_correctness_rate": "Pure protocol correctness (excludes timeouts, reflects cryptographic/security correctness)",
                    "channel_reliability": "Proportion of sessions that complete protocol flow (reflects channel quality)",
                    "key_mismatch_sessions": "Sessions where UAV/ZSP session keys don't match (indicates partial/fake success)",
                }
            },
            "messaging": {
                "total_messages": self.total_messages,
                "avg_size_bytes": round(self.avg_message_size, 2),
                "total_bytes": self.total_bytes,
                "avg_bytes_per_successful_session": round(self.avg_bytes_per_successful_session, 2),
                "avg_messages_per_successful_session": round(self.avg_messages_per_successful_session, 2),
            },
            "timing": {
                "avg_duration_seconds": round(self.avg_duration, 4),
                "min_duration_seconds": round(min_d, 4),
                "max_duration_seconds": round(self.max_duration, 4),
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
                "success_vs_distance": list(self.success_vs_distance),
                "recovery_completion_ratio": round(self.recovery_completion_ratio, 4),
                "reauthentication_cost": dict(self.reauthentication_cost),
            },
            "scalability": {
                "handover_count": self.handover_count,
                "handover_latency_avg_ms": round(self.handover_latency_avg_ms, 2),
                "handover_triggered_reauth_count": self.handover_triggered_reauth_count,
                "topology_change_rate": round(self.topology_change_rate, 4),
                "avg_link_lifetime_s": round(self.avg_link_lifetime_s, 2),
                "density_impact_score": round(self.density_impact_score, 4),
                "_metric_notes": {
                    "handover_count": "Total ZSP handover events (signal strength driven)",
                    "topology_change_rate": "Link change rate per second per UAV (FANET topology dynamicity)",
                    "avg_link_lifetime_s": "Average link duration before handover or disconnection",
                    "density_impact_score": "Impact of network density on performance (0=low, 1=high impact)",
                },
            },
        }


class UAVConfig(BaseModel):
    """UAV 配置"""
    id: int
    mobility: dict


class ZSPConfig(BaseModel):
    """ZSP 配置"""
    id: int
    position: List[float]


class ChannelConfig(BaseModel):
    """通道配置"""
    type: str = "CSMA"
    datarate: str = "100Mbps"
    delay: str = "6560ns"


class SimulationTaskDTO(BaseModel):
    """仿真任务数据传输对象"""
    name: str
    description: Optional[str] = ""
    duration: int = 30
    uavs: List[UAVConfig] = []
    zsps: List[ZSPConfig] = []
    protocol: str = "PMAP"
    channel: ChannelConfig = ChannelConfig()
    scenario: Optional[str] = None
    security_profile: Optional[Dict[str, Any]] = None
