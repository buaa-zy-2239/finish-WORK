# Common/logging_framework.py
"""
通用日志系统框架
- 协议无关的事件类型定义
- 统一的日志结构
- 可扩展的日志管理器

适用于任何UAV认证协议的仿真平台
"""

import json
import time
import os
from enum import Enum
from typing import Optional, Dict, Any

try:
    from ns import ns
    HAS_NS3 = True
except ImportError:
    HAS_NS3 = False


# ============================================================
# 枚举定义 - 协议无关的事件类型
# ============================================================

class LogLevel(Enum):
    """日志级别"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class EntityType(Enum):
    """实体类型"""
    UAV = "UAV"
    ZSP = "ZSP"
    GROUND_STATION = "GROUND_STATION"


class MessageDirection(Enum):
    """消息方向"""
    SEND = "send"
    RECEIVE = "receive"


class AuthenticationPhase(Enum):
    """认证阶段"""
    INITIATED = "initiated"                    # 开始认证
    MESSAGE_SENT = "message_sent"              # 消息已发送
    MESSAGE_RECEIVED = "message_received"      # 消息已接收
    SESSION_ESTABLISHED = "session_established"  # 会话建立
    SUCCESS = "success"                        # 认证成功
    FAILED = "failed"                          # 认证失败


class MobilityEventType(Enum):
    """移动事件类型（仅UAV）"""
    POSITION_UPDATE = "position_update"
    CONNECTED_TO_ZSP = "connected_to_zsp"
    DISCONNECTED_FROM_ZSP = "disconnected_from_zsp"
    HANDOVER = "handover"
    OUT_OF_RANGE = "out_of_range"


class DatabaseOperation(Enum):
    """数据库操作类型（仅ZSP）"""
    REGISTERED = "registered"
    UPDATED = "updated"
    REMOVED = "removed"
    SYNCHRONIZED = "synchronized"


class IdentifierOperation(Enum):
    """标识符操作（如PID、CRP轮换）"""
    REGISTERED = "registered"
    UPDATED = "updated"
    ROTATED = "rotated"


# ============================================================
# 日志条目基类
# ============================================================

class LogEntry:
    """
    统一的日志条目格式
    
    结构：
    {
        "timestamp": float,          # Unix时间戳
        "sim_time": float,           # NS-3模拟时间
        "level": str,                # 日志级别
        "event_type": str,           # 事件类型
        "entity_type": str,          # 实体类型
        "entity_id": int,            # 实体ID
        "details": {                 # 事件详情（协议特定）
            ...
        }
    }
    """
    
    def __init__(self, 
                 level: LogLevel, 
                 event_type: str, 
                 entity_type: EntityType,
                 entity_id: int,
                 details: Optional[Dict[str, Any]] = None):
        """
        初始化日志条目
        
        Args:
            level: 日志级别
            event_type: 事件类型
            entity_type: 实体类型（UAV/ZSP）
            entity_id: 实体ID
            details: 事件详情字典
        """
        self.timestamp = time.time()
        self.sim_time = self._get_sim_time()
        self.level = level.value
        self.event_type = event_type
        self.entity_type = entity_type.value
        self.entity_id = entity_id
        self.details = details or {}
    
    @staticmethod
    def _get_sim_time() -> float:
        """获取NS-3模拟时间"""
        if not HAS_NS3:
            return 0.0
        
        try:
            return ns.Simulator.Now().GetSeconds()
        except:
            return 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "timestamp": self.timestamp,
            "sim_time": self.sim_time,
            "level": self.level,
            "event_type": self.event_type,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "details": self.details
        }
    
    def to_json(self) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), default=str)


# ============================================================
# 日志管理器
# ============================================================

class LogManager:
    """
    统一的日志管理器
    
    特性：
    - 支持多个实体（UAV、ZSP等）同时写日志
    - 每个实体有独立的日志文件
    - JSONL格式存储（每行一个JSON）
    - 高性能行缓冲
    """
    
    def __init__(self, log_dir: str = "/home/zhang/UAV/logs", 
                 sim_id: Optional[int] = None):
        """
        初始化日志管理器
        
        Args:
            log_dir: 日志目录
            sim_id: 仿真ID（用于文件名）
        """
        self.log_dir = log_dir
        self.sim_id = sim_id or int(time.time())
        
        # 创建日志目录
        os.makedirs(log_dir, exist_ok=True)
        
        # 文件句柄缓存：{entity_key: file_handle}
        self._file_handles: Dict[str, Any] = {}
        
        # 日志计数
        self._log_counts: Dict[str, int] = {}
    
    def _get_entity_key(self, entity_type: EntityType, entity_id: int) -> str:
        """生成实体键"""
        return f"{entity_type.value}_{entity_id}"
    
    def _get_or_create_file(self, entity_type: EntityType, 
                           entity_id: int) -> Any:
        """获取或创建日志文件"""
        key = self._get_entity_key(entity_type, entity_id)
        
        if key not in self._file_handles:
            file_path = os.path.join(
                self.log_dir,
                f"sim_{self.sim_id}_{entity_type.value}_{entity_id}.jsonl"
            )
            try:
                self._file_handles[key] = open(file_path, "w", buffering=1)
                self._log_counts[key] = 0
            except Exception as e:
                print(f"[LOG ERROR] Failed to open {file_path}: {e}")
                return None
        
        return self._file_handles[key]
    
    def write(self, log_entry: LogEntry) -> bool:
        """
        写入日志
        
        Args:
            log_entry: 日志条目
            
        Returns:
            是否写入成功
        """
        try:
            file_handle = self._get_or_create_file(
                EntityType(log_entry.entity_type),
                log_entry.entity_id
            )
            
            if not file_handle:
                return False
            
            file_handle.write(log_entry.to_json() + "\n")
            
            key = self._get_entity_key(
                EntityType(log_entry.entity_type),
                log_entry.entity_id
            )
            self._log_counts[key] = self._log_counts.get(key, 0) + 1
            
            return True
        except Exception as e:
            print(f"[LOG ERROR] {e}")
            return False
    
    def flush(self):
        """刷新所有文件"""
        for file_handle in self._file_handles.values():
            try:
                file_handle.flush()
            except:
                pass
    
    def close(self):
        """关闭所有文件"""
        for file_handle in self._file_handles.values():
            try:
                file_handle.close()
            except:
                pass
        self._file_handles.clear()
    
    def get_statistics(self) -> Dict[str, int]:
        """获取日志统计"""
        return self._log_counts.copy()
    
    def __del__(self):
        """析构��数"""
        self.close()


# 全局日志管理器实例
_global_log_manager: Optional[LogManager] = None


def reset_log_manager() -> None:
    """关闭并丢弃全局日志管理器，便于每次仿真任务使用独立目录与 sim_id。"""
    global _global_log_manager
    if _global_log_manager is not None:
        try:
            _global_log_manager.close()
        except Exception:
            pass
        _global_log_manager = None


def get_log_manager(log_dir: str = "/home/zhang/UAV/logs",
                   sim_id: Optional[int] = None) -> LogManager:
    """获取全局日志管理器（单例模式）"""
    global _global_log_manager
    
    if _global_log_manager is None:
        _global_log_manager = LogManager(log_dir, sim_id)
    
    return _global_log_manager


# ============================================================
# 实体日志器基类
# ============================================================

class EntityLogger:
    """
    实体日志器基类
    
    为UAV、ZSP等实体提供统一的日志接口
    """
    
    def __init__(self, entity_type: EntityType, entity_id: int,
                 log_manager: Optional[LogManager] = None):
        """
        初始化实体日志器
        
        Args:
            entity_type: 实体类型
            entity_id: 实体ID
            log_manager: 日志管理器（默认使用全局）
        """
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.log_manager = log_manager or get_log_manager()
    
    def _log(self, level: LogLevel, event_type: str, 
            details: Optional[Dict[str, Any]] = None):
        """
        基础日志方法
        
        Args:
            level: 日志级别
            event_type: 事件类型
            details: 事件详情
        """
        entry = LogEntry(level, event_type, self.entity_type, 
                        self.entity_id, details)
        self.log_manager.write(entry)
    
    # =====================================================
    # 消息日志
    # =====================================================
    
    def log_message_sent(self, message_type: str, payload_size: int,
                        destination: Optional[str] = None,
                        extra: Optional[Dict[str, Any]] = None):
        """记录消息发送"""
        details = {
            "message_type": message_type,
            "direction": MessageDirection.SEND.value,
            "payload_size": payload_size,
            "destination": destination or "broadcast"
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.INFO, "MESSAGE_SENT", details)
    
    def log_message_received(self, message_type: str, payload_size: int,
                            source: Optional[str] = None,
                            extra: Optional[Dict[str, Any]] = None):
        """记录消息接收"""
        details = {
            "message_type": message_type,
            "direction": MessageDirection.RECEIVE.value,
            "payload_size": payload_size,
            "source": source or "unknown"
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.INFO, "MESSAGE_RECEIVED", details)
    
    def log_message_error(self, message_type: str, error_reason: str,
                         payload_size: int = 0,
                         extra: Optional[Dict[str, Any]] = None):
        """记录消息处理错误"""
        details = {
            "message_type": message_type,
            "error_reason": error_reason,
            "payload_size": payload_size
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.ERROR, "MESSAGE_ERROR", details)
    
    # =====================================================
    # 认证日志
    # =====================================================
    
    def log_authentication(self, phase: AuthenticationPhase,
                          success: bool = True,
                          peer_id: Optional[int] = None,
                          extra: Optional[Dict[str, Any]] = None):
        """
        记录认证阶段
        
        Args:
            phase: 认证阶段
            success: 是否成功
            peer_id: 对端实体ID
            extra: 额外信息
        """
        details = {
            "phase": phase.value,
            "status": "success" if success else "failed",
            "peer_id": peer_id
        }
        if extra:
            details.update(extra)
        
        level = LogLevel.INFO if success else LogLevel.WARNING
        event_type = "AUTHENTICATION_SUCCESS" if success else "AUTHENTICATION_FAILED"
        
        self._log(level, event_type, details)
    
    def log_session_established(self, session_id: Optional[str] = None,
                               session_key_hash: Optional[str] = None,
                               duration: Optional[float] = None,
                               peer_id: Optional[int] = None,
                               extra: Optional[Dict[str, Any]] = None):
        """
        记录会话建立
        
        Args:
            session_id: 会话ID
            session_key_hash: 会话密钥的哈希值
            duration: 认证耗时（秒）
            peer_id: 对端实体ID
            extra: 额外信息
        """
        details = {
            "session_id": session_id or "default",
            "session_key_hash": session_key_hash or "unknown",
            "duration_seconds": duration or 0.0,
            "peer_id": peer_id
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.INFO, "SESSION_ESTABLISHED", details)
    
    # =====================================================
    # 标识符操作日志（PID、CRP等）
    # =====================================================
    
    def log_identifier_operation(self, operation: IdentifierOperation,
                                identifier_type: str = "PID",
                                old_value: Optional[str] = None,
                                new_value: Optional[str] = None,
                                extra: Optional[Dict[str, Any]] = None):
        """
        记录标识符操作
        
        Args:
            operation: ���作类型
            identifier_type: 标识符类型（PID/CRP/等）
            old_value: 旧值（取前8个字符）
            new_value: 新值（取前8个字符）
            extra: 额外信息
        """
        details = {
            "identifier_type": identifier_type,
            "operation": operation.value,
            "old_value": old_value[:8] if old_value else None,
            "new_value": new_value[:8] if new_value else None
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.INFO, "IDENTIFIER_OPERATION", details)
    
    # =====================================================
    # 错误和调试日志
    # =====================================================
    
    def log_error(self, error_message: str, error_type: str = "UNKNOWN",
                 extra: Optional[Dict[str, Any]] = None):
        """记录错误"""
        details = {
            "error_message": error_message,
            "error_type": error_type
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.ERROR, "ERROR", details)
    
    def log_warning(self, warning_message: str, warning_type: str = "UNKNOWN",
                   extra: Optional[Dict[str, Any]] = None):
        """记录警告"""
        details = {
            "warning_message": warning_message,
            "warning_type": warning_type
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.WARNING, "WARNING", details)
    
    def log_debug(self, message: str,
                 extra: Optional[Dict[str, Any]] = None):
        """记录调试信息"""
        details = {"message": message}
        if extra:
            details.update(extra)
        
        self._log(LogLevel.DEBUG, "DEBUG", details)


# ============================================================
# UAV专用日志器
# ============================================================

class UAVLogger(EntityLogger):
    """UAV专用日志器"""
    
    def __init__(self, uav_id: int,
                 log_manager: Optional[LogManager] = None):
        super().__init__(EntityType.UAV, uav_id, log_manager)
    
    def log_position_update(self, position: tuple,
                           extra: Optional[Dict[str, Any]] = None):
        """记录位置更新"""
        details = {
            "event_type": MobilityEventType.POSITION_UPDATE.value,
            "position": {
                "x": float(position[0]),
                "y": float(position[1]),
                "z": float(position[2])
            }
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.DEBUG, "MOBILITY_EVENT", details)
    
    def log_connected_to_zsp(self, zsp_id: int,
                            distance: Optional[float] = None,
                            rssi: Optional[float] = None,
                            extra: Optional[Dict[str, Any]] = None):
        """记录连接到ZSP"""
        details = {
            "event_type": MobilityEventType.CONNECTED_TO_ZSP.value,
            "zsp_id": zsp_id,
            "distance": distance,
            "rssi": rssi
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.INFO, "MOBILITY_EVENT", details)
    
    def log_disconnected_from_zsp(self, zsp_id: Optional[int] = None,
                                 reason: Optional[str] = None,
                                 extra: Optional[Dict[str, Any]] = None):
        """记录从ZSP断开连接"""
        details = {
            "event_type": MobilityEventType.DISCONNECTED_FROM_ZSP.value,
            "zsp_id": zsp_id,
            "reason": reason or "unknown"
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.INFO, "MOBILITY_EVENT", details)
    
    def log_handover(self, from_zsp_id: int, to_zsp_id: int,
                    from_rssi: Optional[float] = None,
                    to_rssi: Optional[float] = None,
                    extra: Optional[Dict[str, Any]] = None):
        """记录切换ZSP"""
        details = {
            "event_type": MobilityEventType.HANDOVER.value,
            "from_zsp_id": from_zsp_id,
            "to_zsp_id": to_zsp_id,
            "from_rssi": from_rssi,
            "to_rssi": to_rssi
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.INFO, "MOBILITY_EVENT", details)
    
    def log_out_of_range(self, extra: Optional[Dict[str, Any]] = None):
        """记录超出范围"""
        details = {
            "event_type": MobilityEventType.OUT_OF_RANGE.value
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.WARNING, "MOBILITY_EVENT", details)


# ============================================================
# ZSP专用日志器
# ============================================================

class ZSPLogger(EntityLogger):
    """ZSP专用日志器"""
    
    def __init__(self, zsp_id: int,
                 log_manager: Optional[LogManager] = None):
        super().__init__(EntityType.ZSP, zsp_id, log_manager)
    
    def log_uav_db_operation(self, operation: DatabaseOperation,
                            uav_pid: Optional[str] = None,
                            uav_id: Optional[int] = None,
                            extra: Optional[Dict[str, Any]] = None):
        """记录UAV数据库操作"""
        details = {
            "operation": operation.value,
            "uav_pid": uav_pid[:8] if uav_pid else None,
            "uav_id": uav_id
        }
        if extra:
            details.update(extra)
        
        self._log(LogLevel.INFO, "DATABASE_OPERATION", details)
    
    def log_pid_rotation(self, old_pid: Optional[str] = None,
                        new_pid: Optional[str] = None,
                        old_crp: Optional[list] = None,
                        new_crp: Optional[list] = None,
                        extra: Optional[Dict[str, Any]] = None):
        """记录PID轮换"""
        details = {
            "identifier_type": "PID",
            "operation": IdentifierOperation.ROTATED.value,
            "old_pid": old_pid[:8] if old_pid else None,
            "new_pid": new_pid[:8] if new_pid else None
        }
        
        if old_crp:
            details["old_crp"] = {
                "challenge": float(old_crp[0]) if len(old_crp) > 0 else None,
                "response": float(old_crp[1]) if len(old_crp) > 1 else None
            }
        
        if new_crp:
            details["new_crp"] = {
                "challenge": float(new_crp[0]) if len(new_crp) > 0 else None,
                "response": float(new_crp[1]) if len(new_crp) > 1 else None
            }
        
        if extra:
            details.update(extra)
        
        self._log(LogLevel.INFO, "IDENTIFIER_OPERATION", details)