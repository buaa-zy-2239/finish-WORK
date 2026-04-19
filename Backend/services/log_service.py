# Backend/services/log_service.py
"""
日志服务 - 日志加载和缓存管理
"""

import glob
import os
import time
from pathlib import Path
from threading import Lock
from typing import List, Optional

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
        if getattr(self, "_initialized", False):
            return
        self.log_dir = config.get_log_dir()
        self.active_task_id: Optional[str] = None
        self.events: List[D2ZEvent] = []
        self.analyzer: Optional[D2ZAnalyzer] = None
        self.last_load_time: float = 0
        self.load_interval: float = config.CACHE_UPDATE_INTERVAL
        self._initialized = True
        print(f"[LOG_SERVICE] Initialized with log_dir: {self.log_dir}")

    def _resolve_log_dir(self, task_id: Optional[str]) -> str:
        if task_id:
            p = Path(config.SIMULATION_TASKS_DIR) / task_id / "logs"
            if p.is_dir():
                return str(p)
        return config.get_log_dir()

    def set_active_task(self, task_id: Optional[str]) -> None:
        """设置当前分析所用的仿真任务（None 表示全局默认日志目录）。"""
        self.active_task_id = task_id or None

    def load_logs(self, force_reload: bool = False, task_id: Optional[str] = None) -> bool:
        """
        加载日志文件

        Args:
            force_reload: 是否强制重新加载
            task_id: 若指定，则从该任务目录下的 logs/ 读取
        """
        current_time = time.time()
        tid = task_id if task_id is not None else self.active_task_id
        log_dir = self._resolve_log_dir(tid)
        last_tid = getattr(self, "_last_task_id", None)
        tid_changed = tid != last_tid

        if (
            not force_reload
            and not tid_changed
            and (current_time - self.last_load_time) < self.load_interval
        ):
            return True

        self._last_task_id = tid

        try:
            if not os.path.isdir(log_dir):
                print(f"[LOG_SERVICE] Log directory does not exist: {log_dir}")
                self.events = []
                self.analyzer = None
                self.last_load_time = current_time
                return False

            log_files = glob.glob(os.path.join(log_dir, "*.jsonl"))
            if not log_files:
                print(f"[LOG_SERVICE] No log files found in {log_dir}")
                self.events = []
                self.analyzer = None
                self.last_load_time = current_time
                return True

            print(f"[LOG_SERVICE] Found {len(log_files)} log files in {log_dir}")
            self.events = D2ZLogParser.parse_all_logs(log_dir)
            print(f"[LOG_SERVICE] Loaded {len(self.events)} events")

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

    def get_events(self, limit: int = 100, task_id: Optional[str] = None) -> List[dict]:
        """获取最新事件"""
        self.load_logs(task_id=task_id)
        events = self.events[-limit:] if self.events else []
        return [e.to_dict() for e in events]

    def get_metrics(self, task_id: Optional[str] = None) -> dict:
        """获取全局指标"""
        self.load_logs(task_id=task_id)
        if not self.analyzer:
            return {
                "authentication": {
                    "total_sessions": 0,
                    "successful": 0,
                    "failed": 0,
                    "success_rate_percent": 0.0,
                },
                "messaging": {
                    "total_messages": 0,
                    "avg_size_bytes": 0.0,
                    "total_bytes": 0,
                    "avg_bytes_per_successful_session": 0.0,
                    "avg_messages_per_successful_session": 0.0,
                },
                "timing": {
                    "avg_duration_seconds": 0.0,
                    "min_duration_seconds": 0.0,
                    "max_duration_seconds": 0.0,
                },
                "errors": {
                    "total": 0,
                    "M1_errors": 0,
                    "M2_errors": 0,
                    "M3_M4_errors": 0,
                },
                "triggers": {
                    "breakdown": {},
                },
                "mechanism": {
                    "success_vs_distance": [],
                    "recovery_completion_ratio": 0.0,
                    "reauthentication_cost": {},
                },
            }
        return self.analyzer.get_summary()

    def get_sessions(self, task_id: Optional[str] = None) -> List[dict]:
        """获取所有D2Z会话"""
        self.load_logs(task_id=task_id)
        if not self.analyzer:
            return []
        return self.analyzer.get_all_sessions()

    def get_session_timeline(
        self,
        uav_id: int,
        zsp_id: int,
        session_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> List[dict]:
        """获取会话事件时间线"""
        self.load_logs(task_id=task_id)
        if not self.analyzer:
            return []
        return self.analyzer.get_session_timeline(uav_id, zsp_id, session_id=session_id)

    def get_uav_stats(self, uav_id: int, task_id: Optional[str] = None) -> dict:
        """获取UAV统计"""
        self.load_logs(task_id=task_id)
        if not self.analyzer:
            return {
                "uav_id": uav_id,
                "total_sessions": 0,
                "successful_sessions": 0,
                "failed_sessions": 0,
                "success_rate_percent": 0.0,
                "zsps_connected_to": [],
            }
        return self.analyzer.get_uav_statistics(uav_id)

    def get_log_status(self, task_id: Optional[str] = None) -> dict:
        """获取日志系统状态"""
        self.load_logs(task_id=task_id)
        tid = task_id if task_id is not None else self.active_task_id
        log_dir = self._resolve_log_dir(tid)
        log_files = glob.glob(os.path.join(log_dir, "*.jsonl"))
        return {
            "log_directory": log_dir,
            "task_id": tid,
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


log_service = LogService()
