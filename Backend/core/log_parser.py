# Backend/core/log_parser.py
"""
日志解析器 - 专注D2Z流程
"""

import json
import glob
import os
from typing import List, Optional, Dict, Any
from datetime import datetime

from .event_models import D2ZEvent, D2ZPhase


class D2ZLogParser:
    """D2Z流程日志解析器"""
    
    # D2Z相关的日志事件类型
    D2Z_EVENT_TYPES = {
        "AUTHENTICATION_SUCCESS": "auth",
        "AUTHENTICATION_FAILED": "auth",
        "MESSAGE_SENT": "message",
        "MESSAGE_RECEIVED": "message",
        "MESSAGE_ERROR": "error",
        "SESSION_ESTABLISHED": "session",
    }
    
    @staticmethod
    def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
        """解析单行日志"""
        try:
            data = json.loads(line.strip())
            
            # 校验必需字段
            required_fields = ["timestamp", "sim_time", "level", "event_type", 
                             "entity_type", "entity_id", "details"]
            
            if not all(field in data for field in required_fields):
                return None
            
            return data
        except (json.JSONDecodeError, ValueError, KeyError):
            return None
    
    @staticmethod
    def parse_file(file_path: str) -> List[D2ZEvent]:
        """解析单个日志文件"""
        events = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    raw_data = D2ZLogParser.parse_log_line(line)
                    if raw_data is None:
                        continue
                    
                    # 仅处理D2Z相关事件
                    event = D2ZLogParser._extract_d2z_event(raw_data)
                    if event:
                        events.append(event)
        
        except IOError as e:
            print(f"[ERROR] Failed to read {file_path}: {e}")
        
        return events
    
    @staticmethod
    def _extract_d2z_event(raw_data: Dict[str, Any]) -> Optional[D2ZEvent]:
        """从原始日志数据提取D2Z事件"""
        
        # 非D2Z相关的事件跳过
        event_type = raw_data.get("event_type", "")
        if event_type not in D2ZLogParser.D2Z_EVENT_TYPES:
            return None
        
        # 仅处理UAV的事件（D2Z主要是UAV发起）
        entity_type = raw_data.get("entity_type", "")
        
        timestamp = raw_data.get("timestamp", 0.0)
        sim_time = raw_data.get("sim_time", 0.0)
        entity_id = raw_data.get("entity_id", 0)
        details = raw_data.get("details", {})
        level = raw_data.get("level", "")
        
        # =====================================================
        # 识别D2Z阶段
        # =====================================================
        
        phase = None
        message_type = None
        payload_size = None
        success = True
        error_reason = None
        session_key_hash = None
        zsp_id = details.get("peer_id")
        
        # 认证相关事件
        if event_type == "AUTHENTICATION_SUCCESS":
            auth_phase = details.get("phase", "")
            
            if auth_phase == "initiated":
                phase = D2ZPhase.INITIATED
            elif auth_phase == "message_sent":
                phase = D2ZPhase.M1_SENT
                message_type = details.get("message_type")
                payload_size = details.get("payload_size")
            elif auth_phase == "success":
                phase = D2ZPhase.SUCCESS
                session_key_hash = details.get("session_key_hash")
        
        elif event_type == "AUTHENTICATION_FAILED":
            phase = D2ZPhase.FAILED
            success = False
            error_reason = details.get("error_reason", "Unknown error")
        
        # 消息事件
        elif event_type == "MESSAGE_SENT":
            message_type = details.get("message_type", "")
            payload_size = details.get("payload_size", 0)
            
            if message_type in ["M1", "M3", "M4"]:
                if message_type == "M1":
                    phase = D2ZPhase.M1_SENT
                elif message_type in ["M3", "M4"]:
                    phase = D2ZPhase.M3_M4_SENT
        
        elif event_type == "MESSAGE_RECEIVED":
            message_type = details.get("message_type", "")
            payload_size = details.get("payload_size", 0)
            
            if message_type == "M1":
                phase = D2ZPhase.M1_RECEIVED
                entity_type = "ZSP"  # M1接收者是ZSP
            elif message_type == "M2":
                phase = D2ZPhase.M2_RECEIVED
            elif message_type in ["M3", "M4"]:
                phase = D2ZPhase.M3_M4_RECEIVED
        
        elif event_type == "MESSAGE_ERROR":
            phase = D2ZPhase.FAILED
            success = False
            error_reason = details.get("error_reason", "Message error")
        
        elif event_type == "SESSION_ESTABLISHED":
            phase = D2ZPhase.SESSION_KEY_ESTABLISHED
            session_key_hash = details.get("session_key_hash")
        
        # 未识别的事件跳过
        if phase is None:
            return None
        
        return D2ZEvent(
            timestamp=timestamp,
            sim_time=sim_time,
            uav_id=entity_id if entity_type == "UAV" else -1,
            zsp_id=zsp_id,
            phase=phase,
            message_type=message_type,
            payload_size=payload_size,
            success=success,
            error_reason=error_reason,
            session_key_hash=session_key_hash,
        )
    
    @staticmethod
    def parse_all_logs(log_dir: str) -> List[D2ZEvent]:
        """解析所有日志文件"""
        all_events = []
        
        # 查找所有JSONL日志文件
        log_pattern = os.path.join(log_dir, "sim_*_uav_*.jsonl")
        log_files = glob.glob(log_pattern)
        
        # 也查找ZSP日志
        zsp_pattern = os.path.join(log_dir, "sim_*_zsp_*.jsonl")
        log_files.extend(glob.glob(zsp_pattern))
        
        for log_file in sorted(log_files):
            events = D2ZLogParser.parse_file(log_file)
            all_events.extend(events)
        
        # 按时间排序
        all_events.sort(key=lambda e: e.timestamp)
        
        return all_events