# 在 Backend/core/event_models.py 末尾添加

from pydantic import BaseModel
from typing import List, Optional

# Backend/core/event_models.py
"""
事件数据模型 - 关注D2Z流程
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum

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
    """D2Z认证事��（已解析）"""
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
        }

@dataclass
class D2ZSession:
    """D2Z会话信息"""
    uav_id: int
    zsp_id: int
    start_time: float
    end_time: Optional[float]
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
    
    def to_dict(self) -> Dict[str, Any]:
        return {
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
                "M3_M4": self.m3_m4_size
            },
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
    min_duration: float = float('inf')
    max_duration: float = 0.0
    error_count: int = 0
    m1_errors: int = 0
    m2_errors: int = 0
    m3_m4_errors: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "authentication": {
                "total_sessions": self.total_sessions,
                "successful": self.successful_sessions,
                "failed": self.failed_sessions,
                "success_rate_percent": round(self.success_rate, 2)
            },
            "messaging": {
                "total_messages": self.total_messages,
                "avg_size_bytes": round(self.avg_message_size, 2),
                "total_bytes": self.total_bytes
            },
            "timing": {
                "avg_duration_seconds": round(self.avg_duration, 4),
                "min_duration_seconds": round(self.min_duration, 4),
                "max_duration_seconds": round(self.max_duration, 4)
            },
            "errors": {
                "total": self.error_count,
                "M1_errors": self.m1_errors,
                "M2_errors": self.m2_errors,
                "M3_M4_errors": self.m3_m4_errors
            }
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