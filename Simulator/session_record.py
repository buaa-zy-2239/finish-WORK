"""
会话记录模块 - 定义单个认证会话的数据结构
"""

from typing import Optional, Dict, Any, List


class SessionRecord:
    """单个会话记录"""

    def __init__(self, uav_id: int, zsp_id: int, auth_session_id: str):
        self.uav_id = uav_id
        self.zsp_id = zsp_id
        self.auth_session_id = auth_session_id
        self.zsp_session_id = None

        self.start_time: float = 0.0
        self.end_time: Optional[float] = None

        self.success: Optional[bool] = None
        self.is_timeout: bool = False
        self.error_reason: Optional[str] = None
        self.session_result: str = "pending"

        self.subsession_states: Dict[int, str] = {}
        self.current_subsession_id: int = 0

        self.message_count: int = 0
        self.m1_size: int = 0
        self.m2_size: int = 0
        self.m3_m4_size: int = 0
        self.total_bytes: int = 0

        self.protocol: Optional[str] = None
        self.analysis_family: Optional[str] = None
        self.trigger_reason: Optional[str] = None
        self.trigger_step: Optional[str] = None

        self.uav_session_key_hash: Optional[str] = None
        self.zsp_session_key_hash: Optional[str] = None

        self.init_distance_m: Optional[float] = None
        self.init_rssi: Optional[float] = None
        self.init_link_zone: Optional[str] = None

        self.retry_count: int = 0

        self.events: List[Dict[str, Any]] = []

        self.protocol_state: str = "INIT"
        self.protocol_states: List[Dict[str, Any]] = []

        self.pids: List[str] = []

    @property
    def duration(self) -> float:
        if self.end_time is None:
            return 0.0
        return self.end_time - self.start_time

    def to_dict(self) -> Dict[str, Any]:
        protocol_state = self.protocol_state
        if protocol_state is None and self.protocol_states:
            protocol_state = self.protocol_states[-1].get("new_state", "INIT")
        
        return {
            "uav_id": self.uav_id,
            "zsp_id": self.zsp_id,
            "session_id": self.auth_session_id,
            "auth_session_id": self.auth_session_id,
            "zsp_session_id": self.zsp_session_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration,
            "success": self.success,
            "is_timeout": self.is_timeout,
            "error_reason": self.error_reason,
            "session_result": self.session_result,
            "subsession_states": self.subsession_states,
            "current_subsession_id": self.current_subsession_id,
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
            "protocol_states": self.protocol_states,
            "protocol_state": protocol_state,
        }