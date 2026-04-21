# Backend/api/routes/simulation.py
"""
仿真管理路由 - 处理仿真任务的创建、运行和管理
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from datetime import datetime
import json
import os
import uuid
from pathlib import Path
from typing import Dict, Any
import asyncio
import subprocess
import sys

from config import config
from Common.protocol_registry import get_protocol_spec, list_supported_protocols

router = APIRouter(prefix="/simulation", tags=["simulation"])

# 存储任务信息的字典
tasks_db: Dict[str, Dict[str, Any]] = {}


@router.post("/create")
async def create_simulation_task(task_data: dict) -> dict:
    """
    创建仿真任务
    
    Args:
        task_data: 任务配置数据
    
    Returns:
        dict: 创建的任务信息
    """
    try:
        # 秒级时间戳在快速连点/自动化下会碰撞，追加短 uuid 保证目录唯一
        task_id = f"sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        task_dir = Path(config.SIMULATION_TASKS_DIR) / task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        
        config_file = task_dir / "config.json"
        _protocol = get_protocol_spec(task_data.get("protocol")).name
        config_data = {
            "task_id": task_id,
            "name": task_data.get("name", "Unnamed Task"),
            "created_at": datetime.now().isoformat(),
            "duration": task_data.get("duration", 30),
            "uavs": task_data.get("uavs", []),
            "zsps": task_data.get("zsps", []),
            "simulation": {
                "duration": task_data.get("duration", 30)
            },
            "protocol": _protocol,
            "channel": task_data.get("channel", {"type": "CSMA", "datarate": "100Mbps"}),
            "scenario": task_data.get("scenario"),
            "scenario_profile": task_data.get("scenario_profile"),
            "security_profile": task_data.get("security_profile") or {},
            "attack_model": task_data.get("attack_model"),
        }
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        # 存储任务元数据
        task_metadata = {
            "task_id": task_id,
            "name": config_data.get("name", "Unnamed Task"),
            "task_dir": str(task_dir),
            "config_file": str(config_file),
            "status": "created",
            "created_at": datetime.now().isoformat(),
            "progress": 0
        }
        
        tasks_db[task_id] = task_metadata
        
        print(f"[SIMULATION] Task {task_id} created successfully")
        print(f"[SIMULATION] Config file: {config_file}")
        
        return {
            "success": True,
            "task_id": task_id,
            "config_file": str(config_file),
            "message": "仿真任务创建成功"
        }
    
    except Exception as e:
        print(f"[SIMULATION] Failed to create task: {str(e)}")
        raise HTTPException(status_code=400, detail=f"创建仿真任务失败: {str(e)}")


@router.post("/run/{task_id}")
async def run_simulation(task_id: str, background_tasks: BackgroundTasks) -> dict:
    """运行指定仿真任务"""
    try:
        if task_id not in tasks_db:
            raise HTTPException(status_code=404, detail="仿真任务不存在")
        
        task = tasks_db[task_id]
        config_file = task.get("config_file")
        
        if not config_file or not os.path.exists(config_file):
            raise HTTPException(status_code=404, detail="配置文件不存在")
        
        task["status"] = "running"
        task["started_at"] = datetime.now().isoformat()
        task["progress"] = 0
        
        print(f"[SIMULATION] Starting task {task_id}...")
        
        # 在后台执行仿真
        background_tasks.add_task(_run_simulation_background, task_id, config_file)
        
        return {
            "success": True,
            "task_id": task_id,
            "message": "仿真已启动（后台运行）"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"启动仿真失败: {str(e)}")


@router.get("/status/{task_id}")
async def get_simulation_status(task_id: str) -> dict:
    """获取仿真任务状态"""
    try:
        if task_id not in tasks_db:
            raise HTTPException(status_code=404, detail="仿真任务不存在")
        
        task = tasks_db[task_id]
        
        return {
            "success": True,
            "task_id": task_id,
            "status": task.get("status", "unknown"),
            "progress": task.get("progress", 0),
            "created_at": task.get("created_at"),
            "started_at": task.get("started_at"),
            "completed_at": task.get("completed_at")
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"获取任务状态失败: {str(e)}")


@router.get("/protocols")
async def list_protocols() -> dict:
    return {
        "success": True,
        "protocols": list_supported_protocols(),
    }


@router.get("/list")
async def list_simulation_tasks() -> dict:
    """获取所有仿真任务列表"""
    try:
        tasks = list(tasks_db.values())
        return {
            "success": True,
            "total": len(tasks),
            "tasks": tasks
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"获取任务列表失败: {str(e)}")


@router.get("/config/{task_id}")
async def get_simulation_config(task_id: str) -> dict:
    """获取仿真任务配置"""
    try:
        if task_id not in tasks_db:
            raise HTTPException(status_code=404, detail="仿真任务不存在")
        
        task = tasks_db[task_id]
        config_file = task.get("config_file")
        
        if not config_file or not os.path.exists(config_file):
            raise HTTPException(status_code=404, detail="配置文件不存在")
        
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        
        return {
            "success": True,
            "config": config_data
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"获取配置失败: {str(e)}")


async def _run_simulation_background(task_id: str, config_file: str):
    """
    后台运行仿真 - 使用ns3命令运行仿真器
    
    Args:
        task_id: 仿真任务ID
        config_file: 配置文件路径
    """
    try:
        if task_id not in tasks_db:
            print(f"[SIMULATION] Task {task_id} not found")
            return
        
        task = tasks_db[task_id]
        
        print(f"\n[SIMULATION] ========== Starting simulation {task_id} ==========")
        print(f"[SIMULATION] Config file: {config_file}")

        task_dir = Path(task.get("task_dir", ""))
        log_subdir = task_dir / "logs"
        log_subdir.mkdir(parents=True, exist_ok=True)
        print(f"[SIMULATION] Log directory: {log_subdir}")
        
        try:
            # 获取ns3命令
            ns3_cmd = config.NS3_COMMAND
            simulator_script = config.SIMULATOR_SCRIPT
            
            if not os.path.exists(ns3_cmd):
                raise FileNotFoundError(f"ns3 command not found: {ns3_cmd}")
            
            if not os.path.exists(simulator_script):
                raise FileNotFoundError(f"Simulator script not found: {simulator_script}")
            
            print(f"[SIMULATION] Using ns3: {ns3_cmd}")
            print(f"[SIMULATION] Using simulator: {simulator_script}")
            print(f"[SIMULATION] Config file: {config_file}")
            
            # 构建命令
            cmd = [ns3_cmd, "run", simulator_script]
            
            print(f"[SIMULATION] Running: {' '.join(cmd)}")
            
            # 设置环境变量 - 参考 experiments 中的实现
            env = os.environ.copy()
            env["CONFIG_FILE"] = str(Path(config_file).resolve())
            env["SIM_LOG_DIR"] = str(log_subdir.resolve())
            env["SIM_ID"] = str(abs(hash(task_id)) % (10**9))
            env.setdefault("MALLOC_ARENA_MAX", "2")  # 防止内存分配问题
            
            task["progress"] = 5
            
            # 执行仿真 - 使用 experiments 中的 cwd 设置
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                cwd=str(Path(__file__).resolve().parents[2])  # 项目根目录
            )
            
            print(f"[SIMULATION] ===== Simulation Output Start =====")
            
            for line in process.stdout:
                print(f"[NS3] {line.rstrip()}")
                task["progress"] = min(task["progress"] + 1, 95)
            
            print(f"[SIMULATION] ===== Simulation Output End =====")
            
            # 等待完成
            process.wait(timeout=600)
            
            if process.returncode == 0:
                print(f"[SIMULATION] ✓ Simulator completed successfully")
                task["status"] = "completed"
                task["completed_at"] = datetime.now().isoformat()
                task["progress"] = 100
                
                # 重新加载日志
                try:
                    from services.log_service import log_service
                    log_service.load_logs(force_reload=True, task_id=task_id)
                    print(f"[SIMULATION] ✓ Logs reloaded: {len(log_service.events)} events found")
                except Exception as e:
                    print(f"[SIMULATION] ⚠ Warning: Failed to reload logs: {e}")
                
                print(f"[SIMULATION] ========== Task {task_id} completed ==========\n")
            else:
                print(f"[SIMULATION] ✗ Simulator failed with code {process.returncode}")
                task["status"] = "failed"
                task["error"] = f"Simulator exited with code {process.returncode}"
                task["completed_at"] = datetime.now().isoformat()
                print(f"[SIMULATION] ========== Task {task_id} failed ==========\n")
        
        except subprocess.TimeoutExpired:
            process.kill()
            print(f"[SIMULATION] ✗ Timeout (>10 minutes)")
            task["status"] = "failed"
            task["error"] = "Timeout"
            task["completed_at"] = datetime.now().isoformat()
            print(f"[SIMULATION] ========== Task {task_id} timeout ==========\n")
        
        except Exception as e:
            print(f"[SIMULATION] ✗ Error: {e}")
            task["status"] = "failed"
            task["error"] = str(e)
            task["completed_at"] = datetime.now().isoformat()
            import traceback
            traceback.print_exc()
            print(f"[SIMULATION] ========== Task {task_id} failed ==========\n")
    
    except Exception as e:
        task = tasks_db.get(task_id)
        if task:
            task["status"] = "failed"
            task["error"] = str(e)
            task["completed_at"] = datetime.now().isoformat()
        
        print(f"[SIMULATION] ✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()