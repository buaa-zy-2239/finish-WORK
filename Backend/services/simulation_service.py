# Backend/services/simulation_service.py
"""
仿真执行服务 - 管理仿真任务生命周期
"""

import json
import os
import subprocess
import shutil
import zipfile
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List

from config import config
from services.log_service import log_service


class SimulationService:
    """仿真服务（单例）"""
    
    _instance = None
    _tasks: Dict[str, dict] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def register_task(self, task_id: str, metadata: dict) -> None:
        """注册新任务"""
        self._tasks[task_id] = metadata
    
    def get_task(self, task_id: str) -> Optional[dict]:
        """获取任务元数据"""
        return self._tasks.get(task_id)
    
    def list_tasks(self) -> List[dict]:
        """列出所有任务"""
        return list(self._tasks.values())
    
    def update_task_status(self, task_id: str, status: str, **kwargs) -> None:
        """更新任务状态"""
        if task_id in self._tasks:
            self._tasks[task_id]["status"] = status
            self._tasks[task_id].update(kwargs)
    
    def get_config_file(self, task_id: str) -> str:
        """获取配置文件路径"""
        metadata = self.get_task(task_id)
        if not metadata:
            raise ValueError(f"Task {task_id} not found")
        return metadata["config_file"]
    
    def run_simulation(self, task_id: str, config_file: str) -> bool:
        """
        运行仿真（后台执行）
        
        该方法调用 NS-3 仿真程序
        """
        try:
            self.update_task_status(
                task_id,
                "running",
                started_at=datetime.now().isoformat()
            )
            
            # 调用 Python 脚本运行仿真
            uav_root = Path(__file__).resolve().parent.parent.parent
            script_path = uav_root / "Simulator" / "simulator_builder.py"
            
            result = subprocess.run(
                ["python3", str(script_path)],
                cwd=str(uav_root),
                env={**os.environ, "CONFIG_FILE": config_file},
                capture_output=True,
                text=True,
                timeout=600  # 10分钟超时
            )
            
            if result.returncode == 0:
                self.update_task_status(
                    task_id,
                    "completed",
                    completed_at=datetime.now().isoformat(),
                    progress=100
                )
                
                # 加载日志
                log_service.load_logs(force_reload=True)
                
                return True
            else:
                self.update_task_status(
                    task_id,
                    "failed",
                    error=result.stderr,
                    completed_at=datetime.now().isoformat()
                )
                return False
        
        except subprocess.TimeoutExpired:
            self.update_task_status(task_id, "timeout")
            return False
        except Exception as e:
            self.update_task_status(
                task_id,
                "error",
                error=str(e)
            )
            return False
    
    def package_logs(self, task_id: str) -> str:
        """
        打包仿真日志为 ZIP 文件
        """
        metadata = self.get_task(task_id)
        if not metadata:
            raise ValueError(f"Task {task_id} not found")
        
        log_dir = config.get_log_dir()
        output_file = f"/tmp/{task_id}_logs.zip"
        
        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file in Path(log_dir).glob("*.jsonl"):
                zf.write(file, arcname=file.name)
        
        return output_file
    
    def cleanup_task(self, task_id: str) -> bool:
        """清理任务文件"""
        try:
            metadata = self.get_task(task_id)
            if metadata:
                task_dir = Path(metadata["task_dir"])
                if task_dir.exists():
                    shutil.rmtree(task_dir)
            
            del self._tasks[task_id]
            return True
        except Exception as e:
            print(f"Cleanup failed: {e}")
            return False


# 全局服务实例
simulation_service = SimulationService()