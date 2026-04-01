# backend/simulator_service.py
"""
NS-3 仿真与后端的桥接层
负责：
1. 启动/控制 NS-3 仿真进程
2. 收集仿真日志
3. 提供 REST API
4. 实时推送数据到前端
"""

import json
import subprocess
import os
import asyncio
import threading
import queue
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

# ============================================================
# 数据模型
# ============================================================

@dataclass
class SimulationEvent:
    """仿真事件模型"""
    timestamp: float
    event_type: str  # D2Z_AUTH, D2D_AUTH, PID_UPDATE, SESSION_KEY
    node_id: int
    node_type: str  # UAV, ZSP
    details: Dict

@dataclass
class SimulationMetrics:
    """仿真指标"""
    total_d2z_auths: int = 0
    successful_d2z_auths: int = 0
    total_d2d_auths: int = 0
    successful_d2d_auths: int = 0
    total_pid_updates: int = 0
    total_session_keys_established: int = 0
    simulation_time: float = 0.0

# ============================================================
# 日志解析器
# ============================================================

class LogParser:
    """解析 NS-3 仿真日志"""
    
    @staticmethod
    def parse_log_line(line: str) -> Optional[SimulationEvent]:
        """解析单条日志行"""
        try:
            data = json.loads(line)
            
            # 从日志提取事件类型
            msg = data.get("message", "")
            node_id = data.get("node_id")
            timestamp = data.get("timestamp")
            
            # 识别事件类型
            if "D2Z session key" in msg:
                return SimulationEvent(
                    timestamp=timestamp,
                    event_type="SESSION_KEY",
                    node_id=node_id,
                    node_type="UAV",
                    details={"type": "D2Z", "message": msg}
                )
            elif "D2D session key" in msg:
                return SimulationEvent(
                    timestamp=timestamp,
                    event_type="SESSION_KEY",
                    node_id=node_id,
                    node_type="ZSP",
                    details={"type": "D2D", "message": msg}
                )
            elif "M1" in msg or "M2" in msg or "M3" in msg or "M4" in msg:
                return SimulationEvent(
                    timestamp=timestamp,
                    event_type="D2Z_AUTH",
                    node_id=node_id,
                    node_type="UAV" if "Send" in msg else "ZSP",
                    details={"message": msg}
                )
            elif "D2D M" in msg:
                return SimulationEvent(
                    timestamp=timestamp,
                    event_type="D2D_AUTH",
                    node_id=node_id,
                    node_type="UAV",
                    details={"message": msg}
                )
        except:
            pass
        
        return None

# ============================================================
# 仿真管理器
# ============================================================

class SimulationManager:
    """管理 NS-3 仿真实例"""
    
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.is_running = False
        self.start_time: Optional[datetime] = None
        self.events: List[SimulationEvent] = []
        self.metrics = SimulationMetrics()
        self.event_queue = queue.Queue()
        self.log_files = {}
        
    async def start_simulation(self, config: Dict) -> bool:
        """启动 NS-3 仿真"""
        try:
            # 保存配置
            config_path = "/tmp/ns3_config.json"
            with open(config_path, "w") as f:
                json.dump(config, f)
            
            # 启动仿真进程
            cmd = [
                "python3",
                "/home/zhang/UAV/simulator_builder.py",
                "--config", config_path
            ]
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            self.is_running = True
            self.start_time = datetime.now()
            
            # 启动日志读取线程
            threading.Thread(target=self._read_logs, daemon=True).start()
            
            return True
        except Exception as e:
            print(f"[SIM] Failed to start: {e}")
            return False
    
    def _read_logs(self):
        """读取仿真日志"""
        log_dir = "/tmp/ns3_logs"
        os.makedirs(log_dir, exist_ok=True)
        
        watched_files = {}
        
        while self.is_running:
            try:
                # 找到所有 JSONL 日志文件
                for filename in os.listdir(log_dir):
                    if filename.endswith(".jsonl"):
                        filepath = os.path.join(log_dir, filename)
                        
                        if filepath not in watched_files:
                            watched_files[filepath] = 0
                        
                        # 读取新行
                        with open(filepath, "r") as f:
                            f.seek(watched_files[filepath])
                            for line in f:
                                event = LogParser.parse_log_line(line)
                                if event:
                                    self.events.append(event)
                                    self._update_metrics(event)
                                    self.event_queue.put(asdict(event))
                            
                            watched_files[filepath] = f.tell()
                
                asyncio.sleep(0.1)
            except Exception as e:
                print(f"[LOG] Error: {e}")
    
    def _update_metrics(self, event: SimulationEvent):
        """更新指标"""
        if event.event_type == "D2Z_AUTH":
            self.metrics.total_d2z_auths += 1
        elif event.event_type == "D2D_AUTH":
            self.metrics.total_d2d_auths += 1
        elif event.event_type == "SESSION_KEY":
            self.metrics.total_session_keys_established += 1
    
    def stop_simulation(self):
        """停止仿真"""
        self.is_running = False
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
    
    def get_status(self) -> Dict:
        """获取仿真状态"""
        if not self.is_running or not self.start_time:
            return {
                "status": "stopped",
                "progress": 0,
                "elapsed_time": 0
            }
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        return {
            "status": "running",
            "progress": min(elapsed / 30 * 100, 100),  # 假设 30s 仿真
            "elapsed_time": elapsed,
            "metrics": asdict(self.metrics)
        }
    
    def get_events(self, limit: int = 100) -> List[Dict]:
        """获取最近事件"""
        events = []
        try:
            while len(events) < limit:
                event = self.event_queue.get_nowait()
                events.append(event)
        except queue.Empty:
            pass
        
        return events

# 全局仿真管理器
sim_manager = SimulationManager()