# Backend/services/log_service.py
"""
日志服务 - 日志加载和缓存管理
"""

import time
import os
from typing import List, Optional
from threading import Lock

from ..config import config
from ..core.log_parser import D2ZLogParser
from ..core.event_models import D2ZEvent
from ..analysis.protocol_analyzer import D2ZAnalyzer


class LogService:
    """日志服务（单例）"""
    
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.log_dir = config.get_log_dir()
        self.events: List[D2ZEvent] = []
        self.analyzer: Optional[D2ZAnalyzer] = None
        self.last_load_time: float = 0
        self.load_interval: float = config.CACHE_UPDATE_INTERVAL
        
        self._initialized = True
    
    def load_logs(self, force_reload: bool = False) -> bool:
        """
        加载所有日志文件
        
        Args:
            force_reload: 是否强制重新加载
            
        Returns:
            是否成功加载
        """
        current_time = time.time()
        
        # 检查是否需要重新加载
        if not force_reload and current_time - self.last_load_time < self.load_interval:
            return True
        
        try:
            # 检查日志目录是否存在且有文件
            if not os.path.isdir(self.log_dir):
                return False
            
            # 解析所有日志
            self.events = D2ZLogParser.parse_all_logs(self.log_dir)
            
            # 创建分析器
            if self.events:
                self.analyzer = D2ZAnalyzer(self.events)
            
            self.last_load_time = current_time
            return True
        
        except Exception as e:
            print(f"[ERROR] Failed to load logs: {e}")
            return False
    
    def get_events(self, limit: int = 100) -> List[dict]:
        """获取最新事件"""
        self.load_logs()
        
        events = self.events[-limit:] if self.events else []
        return [e.to_dict() for e in events]
    
    def get_metrics(self) -> dict:
        """获取全局指标"""
        self.load_logs()
        
        if not self.analyzer:
            return {"error": "No data available"}
        
        return self.analyzer.get_summary()
    
    def get_sessions(self) -> List[dict]:
        """获取所有D2Z会话"""
        self.load_logs()
        
        if not self.analyzer:
            return []
        
        return self.analyzer.get_all_sessions()
    
    def get_session_timeline(self, uav_id: int, zsp_id: int) -> List[dict]:
        """获取会话事件时间线"""
        self.load_logs()
        
        if not self.analyzer:
            return []
        
        return self.analyzer.get_session_timeline(uav_id, zsp_id)
    
    def get_uav_stats(self, uav_id: int) -> dict:
        """获取UAV统计"""
        self.load_logs()
        
        if not self.analyzer:
            return {}
        
        return self.analyzer.get_uav_statistics(uav_id)
    
    def get_log_status(self) -> dict:
        """获取日志系统状态"""
        return {
            "log_directory": self.log_dir,
            "total_events": len(self.events),
            "sessions": len(self.analyzer.sessions) if self.analyzer else 0,
            "last_update": self.last_load_time,
        }


# 全局服务实例
log_service = LogService()