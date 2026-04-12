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
    FAILED = "failed"


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
    protocol_step: Optional[str] = None

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
            "protocol_step": self.protocol_step,
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
        }


@dataclass
class D2ZMetrics:
    """D2Z流程指标"""
    total_sessions: int = 0
    successful_sessions: int = 0
    failed_sessions: int = 0
    success_rate: float = 0.0
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

    def to_dict(self) -> Dict[str, Any]:
        min_d = self.min_duration if self.min_duration != float("inf") else 0.0
        return {
            "authentication": {
                "total_sessions": self.total_sessions,
                "successful": self.successful_sessions,
                "failed": self.failed_sessions,
                "success_rate_percent": round(self.success_rate, 2),
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
