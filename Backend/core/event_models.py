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
    INITIATED = "initiated"              # UAV发起认证
    M1_SENT = "M1_sent"                  # M1消息已发送
    M1_RECEIVED = "M1_received"          # ZSP收到M1
    M1_VERIFIED = "M1_verified"          # M1验证成功
    M2_SENT = "M2_sent"                  # M2消息已发送
    M2_RECEIVED = "M2_received"          # UAV收到M2
    M3_M4_SENT = "M3_M4_sent"            # M3/M4消息已发送
    M3_M4_RECEIVED = "M3_M4_received"    # ZSP收到M3/M4
    SESSION_KEY_ESTABLISHED = "session_key_established"  # 会话密钥建立
    SUCCESS = "success"                  # 认证完成
    FAILED = "failed"                    # 认证失败


class MessageType(Enum):
    """消息类型"""
    M1 = "M1"
    M2 = "M2"
    M3 = "M3"
    M4 = "M4"


@dataclass
class D2ZEvent:
    """D2Z认证事件（已解析）"""
    
    # 基础信息
    timestamp: float              # Unix时间戳
    sim_time: float              # NS-3模拟时间
    uav_id: int                  # UAV ID
    zsp_id: Optional[int]        # ZSP ID（初期可能为None）
    phase: D2ZPhase              # 认证阶段
    
    # 消息信息
    message_type: Optional[str]  # M1/M2/M3/M4
    payload_size: Optional[int]  # 消息大小
    
    # 认证信息
    success: bool = True         # 是否成功
    error_reason: Optional[str] = None  # 失败原因
    
    # 会话信息
    session_key_hash: Optional[str] = None  # 会话密钥哈希（安全考量）
    
    @property
    def datetime_str(self) -> str:
        """可读的时间戳"""
        return datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    @property
    def event_id(self) -> str:
        """事件唯一ID"""
        return f"D2Z_{self.uav_id}_{self.phase.value}_{self.timestamp}"
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
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
    start_time: float           # 认证开始时间
    end_time: Optional[float]   # 认证结束时间
    
    total_events: int = 0       # 事件数
    message_count: int = 0      # 消息数
    m1_size: int = 0           # M1大小
    m2_size: int = 0           # M2大小
    m3_m4_size: int = 0        # M3/M4大小
    
    success: bool = False       # 是否成功
    error_reason: Optional[str] = None
    session_key_hash: Optional[str] = None
    
    @property
    def duration(self) -> float:
        """认证耗时（秒）"""
        if self.end_time is None:
            return 0.0
        return self.end_time - self.start_time
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
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
    
    # 认证统计
    total_sessions: int = 0
    successful_sessions: int = 0
    failed_sessions: int = 0
    success_rate: float = 0.0  # 百分比
    
    # 消息统计
    total_messages: int = 0
    avg_message_size: float = 0.0
    total_bytes: int = 0
    
    # 时间统计
    avg_duration: float = 0.0
    min_duration: float = float('inf')
    max_duration: float = 0.0
    
    # 错误统计
    error_count: int = 0
    m1_errors: int = 0
    m2_errors: int = 0
    m3_m4_errors: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
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