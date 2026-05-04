"""
仿真管理路由 - 处理仿真任务的创建、运行和管理
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from datetime import datetime
import json
import os
import subprocess
import uuid
from pathlib import Path

from config import config
from di import get_service
from exceptions import TaskNotFoundError, ConfigFileNotFoundError, ProtocolNotSupportedError
from Common.protocol_registry import get_protocol_spec, list_supported_protocols

router = APIRouter(prefix="/simulation", tags=["simulation"])


async def get_simulation_service():
    """获取仿真服务"""
    return get_service('simulation_service')


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
        task_id = f"sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        task_dir = Path(config.SIMULATION_TASKS_DIR) / task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        
        config_file = task_dir / "config.json"
        
        _protocol = task_data.get("protocol")
        if not _protocol:
            raise ProtocolNotSupportedError("未指定协议")
        
        protocol_spec = get_protocol_spec(_protocol)
        if not protocol_spec:
            raise ProtocolNotSupportedError(_protocol)
        
        enable_blockchain = task_data.get("enable_blockchain", False)
        if protocol_spec.name in ["RLBA_UAV", "RLBA_3WAY"]:
            enable_blockchain = True
        
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
            "protocol": protocol_spec.name,
            "channel": task_data.get("channel", {"type": "CSMA", "datarate": "100Mbps"}),
            "scenario": task_data.get("scenario"),
            "scenario_profile": task_data.get("scenario_profile"),
            "security_profile": task_data.get("security_profile") or {},
            "attack_model": task_data.get("attack_model"),
            "user_count": task_data.get("user_count", 0),
            "enable_blockchain": enable_blockchain,
        }
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        task_metadata = {
            "task_id": task_id,
            "name": config_data.get("name", "Unnamed Task"),
            "task_dir": str(task_dir),
            "config_file": str(config_file),
            "status": "created",
            "created_at": datetime.now().isoformat(),
            "progress": 0
        }
        
        simulation_service = get_service('simulation_service')
        simulation_service.register_task(task_id, task_metadata)
        
        print(f"[SIMULATION] Task {task_id} created successfully")
        
        return {
            "success": True,
            "task_id": task_id,
            "config_file": str(config_file),
            "message": "仿真任务创建成功"
        }
    
    except ProtocolNotSupportedError as e:
        raise HTTPException(status_code=400, detail=e.message)
    except Exception as e:
        print(f"[SIMULATION] Failed to create task: {str(e)}")
        raise HTTPException(status_code=400, detail=f"创建仿真任务失败: {str(e)}")


@router.post("/run/{task_id}")
async def run_simulation(
    task_id: str, 
    background_tasks: BackgroundTasks
) -> dict:
    """运行指定仿真任务"""
    try:
        simulation_service = get_service('simulation_service')
        
        try:
            task = simulation_service.get_task(task_id)
        except TaskNotFoundError as e:
            raise HTTPException(status_code=404, detail=e.message)
        
        config_file = task.get("config_file")
        if not config_file or not os.path.exists(config_file):
            raise ConfigFileNotFoundError(config_file or "unknown")
        
        task["status"] = "running"
        task["started_at"] = datetime.now().isoformat()
        task["progress"] = 0
        
        print(f"[SIMULATION] Starting task {task_id}...")
        
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
        simulation_service = get_service('simulation_service')
        
        try:
            task = simulation_service.get_task(task_id)
        except TaskNotFoundError as e:
            raise HTTPException(status_code=404, detail=e.message)
        
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
        simulation_service = get_service('simulation_service')
        tasks = simulation_service.list_tasks()
        
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
        simulation_service = get_service('simulation_service')
        
        try:
            task = simulation_service.get_task(task_id)
        except TaskNotFoundError as e:
            raise HTTPException(status_code=404, detail=e.message)
        
        config_file = task.get("config_file")
        if not config_file or not os.path.exists(config_file):
            raise ConfigFileNotFoundError(config_file or "unknown")
        
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
    """
    try:
        simulation_service = get_service('simulation_service')
        
        try:
            task = simulation_service.get_task(task_id)
        except TaskNotFoundError:
            print(f"[SIMULATION] Task {task_id} not found")
            return
        
        print(f"\n[SIMULATION] ========== Starting simulation {task_id} ==========")
        print(f"[SIMULATION] Config file: {config_file}")

        task_dir = Path(task.get("task_dir", ""))
        log_subdir = task_dir / "logs"
        log_subdir.mkdir(parents=True, exist_ok=True)
        
        try:
            ns3_cmd = config.NS3_COMMAND
            simulator_script = config.SIMULATOR_SCRIPT
            
            if not os.path.exists(ns3_cmd):
                raise FileNotFoundError(f"ns3 command not found: {ns3_cmd}")
            
            if not os.path.exists(simulator_script):
                raise FileNotFoundError(f"Simulator script not found: {simulator_script}")
            
            cmd = [ns3_cmd, "run", simulator_script]
            
            print(f"[SIMULATION] Running: {' '.join(cmd)}")
            
            env = os.environ.copy()
            env["CONFIG_FILE"] = str(Path(config_file).resolve())
            env["SIM_LOG_DIR"] = str(log_subdir.resolve())
            env["SIM_ID"] = str(abs(hash(task_id)) % (10**9))
            env.setdefault("MALLOC_ARENA_MAX", "2")
            
            task["progress"] = 5
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                cwd=str(Path(__file__).resolve().parents[2])
            )
            
            print(f"[SIMULATION] ===== Simulation Output Start =====")
            
            for line in process.stdout:
                print(f"[NS3] {line.rstrip()}")
                task["progress"] = min(task["progress"] + 1, 95)
            
            print(f"[SIMULATION] ===== Simulation Output End =====")
            
            process.wait(timeout=600)
            
            if process.returncode == 0:
                print(f"[SIMULATION] ✓ Simulator completed successfully")
                task["status"] = "completed"
                task["completed_at"] = datetime.now().isoformat()
                task["progress"] = 100
                
                log_service = get_service('log_service')
                log_service.load_logs(force_reload=True, task_id=task_id)
                
                print(f"[SIMULATION] ========== Task {task_id} completed ==========\n")
            else:
                print(f"[SIMULATION] ✗ Simulator failed with code {process.returncode}")
                task["status"] = "failed"
                task["error"] = f"Simulator exited with code {process.returncode}"
                task["completed_at"] = datetime.now().isoformat()
        
        except subprocess.TimeoutExpired:
            process.kill()
            print(f"[SIMULATION] ✗ Timeout (>10 minutes)")
            task["status"] = "failed"
            task["error"] = "Timeout"
            task["completed_at"] = datetime.now().isoformat()
        
        except Exception as e:
            print(f"[SIMULATION] ✗ Error: {e}")
            task["status"] = "failed"
            task["error"] = str(e)
            task["completed_at"] = datetime.now().isoformat()
            import traceback
            traceback.print_exc()
    
    except Exception as e:
        print(f"[SIMULATION] ✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()