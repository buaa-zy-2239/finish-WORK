# Backend/services/log_service.py
"""
日志服务 - 日志加载和缓存管理
"""

import time
import os
import glob
from typing import List, Optional
from threading import Lock

from config import config
from core.log_parser import D2ZLogParser
from core.event_models import D2ZEvent
from analysis.protocol_analyzer import D2ZAnalyzer


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
        
        # 使用正确的日志路径
        self.log_dir = config.get_log_dir()
        self.events: List[D2ZEvent] = []
        self.analyzer: Optional[D2ZAnalyzer] = None
        self.last_load_time: float = 0
        self.load_interval: float = config.CACHE_UPDATE_INTERVAL
        
        self._initialized = True
        print(f"[LOG_SERVICE] Initialized with log_dir: {self.log_dir}")
    
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
                print(f"[LOG_SERVICE] Log directory does not exist: {self.log_dir}")
                return False
            
            # 列出所有日志文件
            log_files = glob.glob(os.path.join(self.log_dir, "*.jsonl"))
            
            if not log_files:
                print(f"[LOG_SERVICE] No log files found in {self.log_dir}")
                self.events = []
                self.analyzer = None
                self.last_load_time = current_time
                return True
            
            print(f"[LOG_SERVICE] Found {len(log_files)} log files in {self.log_dir}")
            
            # 解析所有日志
            self.events = D2ZLogParser.parse_all_logs(self.log_dir)
            print(f"[LOG_SERVICE] Loaded {len(self.events)} events")
            
            # 创建分析器
            if self.events:
                self.analyzer = D2ZAnalyzer(self.events)
                print(f"[LOG_SERVICE] Analysis completed with {len(self.analyzer.sessions)} sessions")
            else:
                self.analyzer = None
                print("[LOG_SERVICE] No events found after parsing")
            
            self.last_load_time = current_time
            return True
        
        except Exception as e:
            print(f"[LOG_SERVICE] Failed to load logs: {e}")
            import traceback
            traceback.print_exc()
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
            return {
                "authentication": {
                    "total_sessions": 0,
                    "successful": 0,
                    "failed": 0,
                    "success_rate_percent": 0.0
                },
                "messaging": {
                    "total_messages": 0,
                    "avg_size_bytes": 0.0,
                    "total_bytes": 0
                },
                "timing": {
                    "avg_duration_seconds": 0.0,
                    "min_duration_seconds": 0.0,
                    "max_duration_seconds": 0.0
                },
                "errors": {
                    "total": 0,
                    "M1_errors": 0,
                    "M2_errors": 0,
                    "M3_M4_errors": 0
                }
            }
        
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
            return {
                "uav_id": uav_id,
                "total_sessions": 0,
                "successful_sessions": 0,
                "failed_sessions": 0,
                "success_rate_percent": 0.0,
                "zsps_connected_to": []
            }
        
        return self.analyzer.get_uav_statistics(uav_id)
    
    def get_log_status(self) -> dict:
        """获取日志系统状态"""
        self.load_logs()
        
        log_files = glob.glob(os.path.join(self.log_dir, "*.jsonl"))
        
        return {
            "log_directory": self.log_dir,
            "log_files": len(log_files),
            "total_events": len(self.events),
            "sessions": len(self.analyzer.sessions) if self.analyzer else 0,
            "last_update": self.last_load_time,
        }
    
    def clear_cache(self) -> bool:
        """清空缓存"""
        try:
            self.events = []
            self.analyzer = None
            self.last_load_time = 0
            print("[LOG_SERVICE] Cache cleared")
            return True
        except Exception as e:
            print(f"[LOG_SERVICE] Failed to clear cache: {e}")
            return False


# 全局服务实例
log_service = LogService()