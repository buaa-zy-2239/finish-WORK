"""
SessionTracker跟踪Mixin - 提供统一的会话跟踪接口
"""

import weakref
from typing import Optional, Any


class UAVSessionTrackerMixin:
    """UAV会话跟踪Mixin"""

    def _init_session_tracker(self, session_tracker: Any):
        """初始化SessionTracker引用"""
        self._session_tracker = weakref.ref(session_tracker) if session_tracker else None

    def _get_session_tracker(self):
        """获取SessionTracker实例"""
        if self._session_tracker:
            return self._session_tracker()
        return None

    def _get_current_session_id(self) -> Optional[str]:
        """获取当前会话ID"""
        tracker = self._get_session_tracker()
        if tracker and hasattr(self, 'zsp_id') and self.zsp_id:
            try:
                return tracker.get_session_id_by_pair(self.id, self.zsp_id)
            except Exception:
                pass
        return getattr(self, 'd2z_auth_session_id', None)

    def _track_session_start(self, trigger_step: str = None, is_retry: bool = False):
        """通知Tracker会话开始"""
        tracker = self._get_session_tracker()
        if tracker and hasattr(self, 'zsp_id') and self.zsp_id:
            try:
                from ns import ns
                sim_time = ns.Simulator.Now().GetSeconds()
                session_id = tracker.start_session_by_pair(
                    uav_id=self.id,
                    zsp_id=self.zsp_id,
                    sim_time=sim_time,
                    protocol=getattr(self, 'protocol_name', 'PMAP'),
                    analysis_family=getattr(self, 'analysis_family', 'D2Z'),
                    trigger_step=trigger_step,
                    is_retry=is_retry,
                )
                self.d2z_auth_session_id = session_id
            except Exception:
                pass

    def _track_session_end(self, success: bool, error_reason: str = None, is_timeout: bool = False):
        """通知Tracker会话结束"""
        tracker = self._get_session_tracker()
        if tracker:
            try:
                from ns import ns
                sim_time = ns.Simulator.Now().GetSeconds()
                session_id = self._get_current_session_id()
                tracker.end_session(
                    auth_session_id=session_id,
                    sim_time=sim_time,
                    success=success,
                    error_reason=error_reason,
                    is_timeout=is_timeout,
                )
            except Exception:
                pass

    def _track_message(self, message_type: str, payload_size: int, direction: str = "send"):
        """通知Tracker消息发送/接收"""
        tracker = self._get_session_tracker()
        if tracker:
            try:
                from ns import ns
                sim_time = ns.Simulator.Now().GetSeconds()
                session_id = self._get_current_session_id()
                tracker.record_message(
                    auth_session_id=session_id,
                    message_type=message_type,
                    payload_size=payload_size,
                    sim_time=sim_time,
                    direction=direction,
                    entity_type="UAV",
                )
            except Exception:
                pass

    def _track_session_key(self, session_key_hash: str):
        """通知Tracker会话密钥建立"""
        tracker = self._get_session_tracker()
        if tracker:
            try:
                from ns import ns
                sim_time = ns.Simulator.Now().GetSeconds()
                session_id = self._get_current_session_id()
                tracker.record_session_key(
                    auth_session_id=session_id,
                    session_key_hash=session_key_hash,
                    sim_time=sim_time,
                    entity_type="UAV",
                )
            except Exception:
                pass

    def _track_error(self, error_type: str, error_reason: str, message_type: str = None):
        """通知Tracker错误事件"""
        tracker = self._get_session_tracker()
        if tracker:
            try:
                from ns import ns
                sim_time = ns.Simulator.Now().GetSeconds()
                session_id = self._get_current_session_id()
                tracker.record_error(
                    auth_session_id=session_id,
                    error_type=error_type,
                    error_reason=error_reason,
                    sim_time=sim_time,
                    message_type=message_type,
                )
            except Exception:
                pass

    def _update_protocol_state(self, new_state: str, message_type: str = None,
                               error_type: str = None, error_reason: str = None):
        """通知Tracker更新协议状态"""
        tracker = self._get_session_tracker()
        if tracker:
            try:
                from ns import ns
                sim_time = ns.Simulator.Now().GetSeconds()
                session_id = self._get_current_session_id()
                tracker.update_protocol_state(
                    auth_session_id=session_id,
                    new_state=new_state,
                    sim_time=sim_time,
                    message_type=message_type,
                    error_type=error_type,
                    error_reason=error_reason,
                )
            except Exception:
                pass

    def _register_pid_mapping(self):
        """向SessionTracker注册PID映射"""
        tracker = self._get_session_tracker()
        if tracker and hasattr(self, 'zsp_id') and self.zsp_id:
            try:
                tracker.register_pid(getattr(self, 'pid', None), self.id, self.zsp_id)
            except Exception:
                pass


class ZSPSessionTrackerMixin:
    """ZSP会话跟踪Mixin"""

    def _init_session_tracker(self, session_tracker: Any):
        """初始化SessionTracker引用"""
        self._session_tracker = weakref.ref(session_tracker) if session_tracker else None

    def _get_session_tracker(self):
        """获取SessionTracker实例"""
        if self._session_tracker:
            return self._session_tracker()
        return None

    def _get_session_id_by_uav_id(self, uav_id: int) -> Optional[str]:
        """通过UAV ID获取会话ID"""
        tracker = self._get_session_tracker()
        if tracker:
            try:
                return tracker.get_session_id_by_pair(uav_id, self.zsp_id)
            except Exception:
                pass
        return None

    def _track_message(self, uav_id: int, message_type: str, payload_size: int, direction: str = "send"):
        """通知Tracker消息发送/接收"""
        tracker = self._get_session_tracker()
        if tracker:
            try:
                from ns import ns
                sim_time = ns.Simulator.Now().GetSeconds()
                session_id = self._get_session_id_by_uav_id(uav_id)
                if session_id:
                    tracker.record_message(
                        auth_session_id=session_id,
                        message_type=message_type,
                        payload_size=payload_size,
                        sim_time=sim_time,
                        direction=direction,
                        entity_type="ZSP",
                    )
            except Exception:
                pass

    def _track_session_key(self, uav_id: int, session_key_hash: str, zsp_session_id: str):
        """通知Tracker会话密钥建立"""
        tracker = self._get_session_tracker()
        if tracker:
            try:
                from ns import ns
                sim_time = ns.Simulator.Now().GetSeconds()
                session_id = self._get_session_id_by_uav_id(uav_id)
                if session_id:
                    tracker.record_session_key(
                        auth_session_id=session_id,
                        session_key_hash=session_key_hash,
                        sim_time=sim_time,
                        entity_type="ZSP",
                        zsp_session_id=zsp_session_id,
                    )
            except Exception:
                pass

    def _track_session_end(self, uav_id: int, success: bool, error_reason: str = None, is_timeout: bool = False):
        """通知Tracker会话结束"""
        tracker = self._get_session_tracker()
        if tracker:
            try:
                from ns import ns
                sim_time = ns.Simulator.Now().GetSeconds()
                session_id = self._get_session_id_by_uav_id(uav_id)
                if session_id:
                    tracker.end_session(
                        auth_session_id=session_id,
                        sim_time=sim_time,
                        success=success,
                        error_reason=error_reason,
                        is_timeout=is_timeout,
                    )
            except Exception:
                pass

    def _track_error(self, uav_id: int, error_type: str, error_reason: str, message_type: str = None):
        """通知Tracker错误事件"""
        tracker = self._get_session_tracker()
        if tracker:
            try:
                from ns import ns
                sim_time = ns.Simulator.Now().GetSeconds()
                session_id = self._get_session_id_by_uav_id(uav_id) if uav_id else None
                tracker.record_error(
                    auth_session_id=session_id,
                    error_type=error_type,
                    error_reason=error_reason,
                    sim_time=sim_time,
                    message_type=message_type,
                )
            except Exception:
                pass

    def _update_protocol_state(self, uav_id: int, new_state: str, message_type: str = None,
                               error_type: str = None, error_reason: str = None, pid: str = None):
        """通知Tracker更新协议状态"""
        tracker = self._get_session_tracker()
        if tracker:
            try:
                from ns import ns
                sim_time = ns.Simulator.Now().GetSeconds()
                session_id = None
                
                if uav_id:
                    session_id = self._get_session_id_by_uav_id(uav_id)
                
                if not session_id and pid:
                    session_info = tracker.resolve_session_by_pid(pid)
                    if session_info:
                        session_id = session_info.auth_session_id
                
                if session_id:
                    tracker.update_protocol_state(
                        auth_session_id=session_id,
                        new_state=new_state,
                        sim_time=sim_time,
                        message_type=message_type,
                        error_type=error_type,
                        error_reason=error_reason,
                    )
            except Exception:
                pass