# backend/main.py
from fastapi import FastAPI, WebSocket, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import json

app = FastAPI(title="UAV Simulation Dashboard API")

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# Pydantic 模型
# ============================================================

class UAVConfigModel(BaseModel):
    id: int
    mobility: dict

class ZSPConfigModel(BaseModel):
    id: int
    position: List[float]

class SimulationConfigModel(BaseModel):
    uavs: List[UAVConfigModel]
    zsps: List[ZSPConfigModel]
    duration: int

class SimulationStatusModel(BaseModel):
    status: str
    progress: float
    elapsed_time: float
    metrics: Optional[dict] = None

# ============================================================
# 配置 API
# ============================================================

@app.get("/api/config/template")
async def get_config_template():
    """获取默认配置模板"""
    return {
        "uavs": [
            {
                "id": 0,
                "mobility": {
                    "type": "waypoint",
                    "waypoints": [
                        [0, [0, 0, 50]],
                        [15, [400, 0, 50]],
                        [30, [800, 200, 50]]
                    ]
                }
            }
        ],
        "zsps": [
            {
                "id": 1,
                "position": [0, 0, 100]
            }
        ],
        "duration": 30
    }

@app.post("/api/config/save")
async def save_config(config: SimulationConfigModel):
    """保存配置"""
    config_dict = {
        "uavs": [asdict(u) for u in config.uavs],
        "zsps": [asdict(z) for z in config.zsps],
        "simulation": {"duration": config.duration}
    }
    return {"message": "Config saved", "config": config_dict}

# ============================================================
# 仿真控制 API
# ============================================================

@app.post("/api/simulation/start")
async def start_simulation(
    config: SimulationConfigModel,
    background_tasks: BackgroundTasks
):
    """启动仿真"""
    config_dict = {
        "uavs": [dict(u) for u in config.uavs],
        "zsps": [dict(z) for z in config.zsps],
        "simulation": {"duration": config.duration}
    }
    
    success = await sim_manager.start_simulation(config_dict)
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to start simulation")
    
    return {"message": "Simulation started"}

@app.post("/api/simulation/stop")
async def stop_simulation():
    """停止仿真"""
    sim_manager.stop_simulation()
    return {"message": "Simulation stopped"}

@app.get("/api/simulation/status", response_model=SimulationStatusModel)
async def get_simulation_status():
    """获取仿真状态"""
    status = sim_manager.get_status()
    return SimulationStatusModel(**status)

# ============================================================
# 事件/日志 API
# ============================================================

@app.get("/api/events/latest")
async def get_latest_events(limit: int = 100):
    """获取最新事件"""
    events = sim_manager.get_events(limit)
    return {"events": events}

@app.get("/api/metrics")
async def get_metrics():
    """获取指标汇总"""
    return asdict(sim_manager.metrics)

# ============================================================
# WebSocket
# ============================================================

websocket_clients = set()

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket: 实时事件流"""
    await websocket.accept()
    websocket_clients.add(websocket)
    
    try:
        while True:
            events = sim_manager.get_events(limit=1)
            if events:
                await websocket.send_json({"type": "event", "data": events})
            await asyncio.sleep(0.1)
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        websocket_clients.discard(websocket)

@app.websocket("/ws/status")
async def websocket_status(websocket: WebSocket):
    """WebSocket: 实时状态更新"""
    await websocket.accept()
    
    try:
        while True:
            status = sim_manager.get_status()
            await websocket.send_json({
                "type": "status",
                "data": status
            })
            await asyncio.sleep(1)
    except Exception as e:
        print(f"WebSocket error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)