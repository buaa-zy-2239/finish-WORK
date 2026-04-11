# Backend/api/routes/simulation.py
"""
仿真控制路由 - 创建、运行、停止仿真任务
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, File, UploadFile
from fastapi.responses import FileResponse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from config import config
from services.simulation_service import SimulationService
from core.event_models import SimulationTaskDTO

router = APIRouter(prefix="/simulation", tags=["simulation"])
sim_service = SimulationService()


@router.post("/create")
async def create_simulation_task(task_data: dict) -> dict:
    """
    创建仿真任务
    
    Args:
        task_data: {
            "name": "任务名称",
            "description": "任务描述",
            "duration": 仿真时长(秒),
            "uavs": [
                {"id": 0, "mobility": {"type": "waypoint", "waypoints": [...]}},
                ...
            ],
            "zsps": [
                {"id": 2, "position": [x, y, z]},
                ...
            ],
            "protocol": "PMAP",
            "channel": {"type": "CSMA", "datarate": "100Mbps"}
        }
    """
    try:
        # 创建任务目录
        task_id = f"sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        task_dir = Path(config.SIMULATION_TASKS_DIR) / task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        
        # 保存配置文件
        config_file = task_dir / "config.json"
        config_data = {
            "task_id": task_id,
            "name": task_data.get("name", "Unnamed Task"),
            "description": task_data.get("description", ""),
            "created_at": datetime.now().isoformat(),
            "duration": task_data.get("duration", 30),
            "uavs": task_data.get("uavs", []),
            "zsps": task_data.get("zsps", []),
            "simulation": {
                "duration": task_data.get("duration", 30)
            },
            "protocol": task_data.get("protocol", "PMAP"),
            "channel": task_data.get("channel", {"type": "CSMA", "datarate": "100Mbps"})
        }
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        # 存储任务元数据
        metadata = {
            "task_id": task_id,
            "task_dir": str(task_dir),
            "config_file": str(config_file),
            "status": "created",
            "created_at": datetime.now().isoformat()
        }
        
        sim_service.register_task(task_id, metadata)
        
        return {
            "success": True,
            "task_id": task_id,
            "config_file": str(config_file),
            "message": "仿真任务创建成功"
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"创建仿真任务失败: {str(e)}"
        )


@router.post("/run/{task_id}")
async def run_simulation(task_id: str, background_tasks: BackgroundTasks) -> dict:
    """
    运行指定仿真任务
    """
    try:
        metadata = sim_service.get_task(task_id)
        if not metadata:
            raise HTTPException(status_code=404, detail="仿真任务不存在")
        
        config_file = metadata["config_file"]
        
        # 后台运行仿真
        background_tasks.add_task(sim_service.run_simulation, task_id, config_file)
        
        sim_service.update_task_status(task_id, "running")
        
        return {
            "success": True,
            "task_id": task_id,
            "message": "仿真已启动（后台运行）"
        }
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/status/{task_id}")
async def get_simulation_status(task_id: str) -> dict:
    """获取仿真任务状态"""
    try:
        metadata = sim_service.get_task(task_id)
        if not metadata:
            raise HTTPException(status_code=404, detail="仿真任务不存在")
        
        return {
            "task_id": task_id,
            "status": metadata.get("status", "unknown"),
            "progress": metadata.get("progress", 0),
            "created_at": metadata.get("created_at"),
            "started_at": metadata.get("started_at"),
            "completed_at": metadata.get("completed_at")
        }
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/list")
async def list_simulation_tasks() -> dict:
    """获取所有仿真任务列表"""
    tasks = sim_service.list_tasks()
    return {
        "success": True,
        "total": len(tasks),
        "tasks": tasks
    }


@router.get("/config/{task_id}")
async def get_simulation_config(task_id: str) -> dict:
    """获取仿真任务配置"""
    try:
        config_path = sim_service.get_config_file(task_id)
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        return {
            "success": True,
            "config": config_data
        }
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/download-logs/{task_id}")
async def download_simulation_logs(task_id: str) -> FileResponse:
    """下载仿真日志"""
    try:
        logs_file = sim_service.package_logs(task_id)
        return FileResponse(
            path=logs_file,
            filename=f"{task_id}_logs.zip",
            media_type="application/zip"
        )
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))