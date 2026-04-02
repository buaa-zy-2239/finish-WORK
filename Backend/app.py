# Backend/app.py
"""
FastAPI主应用
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import asyncio

from config import config
from api.routes import events, metrics, health
from services.log_service import log_service


# 创建应用
app = FastAPI(
    title=config.APP_NAME,
    version=config.APP_VERSION,
    debug=config.DEBUG,
)

# CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# 路由注册
# ============================================================

app.include_router(health.router)
app.include_router(events.router, prefix=config.API_V1_PREFIX)
app.include_router(metrics.router, prefix=config.API_V1_PREFIX)

# ============================================================
# 启动和关闭事件
# ============================================================

@app.on_event("startup")
async def startup_event():
    """应用启动"""
    print(f"[STARTUP] {config.APP_NAME} v{config.APP_VERSION}")
    
    # 初始加载日志
    log_service.load_logs(force_reload=True)
    print("[STARTUP] Logs loaded successfully")


@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭"""
    print("[SHUTDOWN] Shutting down...")


# ============================================================
# WebSocket - 实时事件推送
# ============================================================

@app.websocket("/ws/d2z-events")
async def websocket_d2z_events(websocket):
    """WebSocket: D2Z事件实时推送"""
    await websocket.accept()
    
    last_event_count = len(log_service.events)
    
    try:
        while True:
            # 每秒检查新事件
            await asyncio.sleep(1)
            
            log_service.load_logs()
            current_event_count = len(log_service.events)
            
            if current_event_count > last_event_count:
                new_events = log_service.events[last_event_count:]
                await websocket.send_json({
                    "type": "new_events",
                    "count": len(new_events),
                    "events": [e.to_dict() for e in new_events]
                })
                last_event_count = current_event_count
    
    except Exception as e:
        print(f"[WS] Connection error: {e}")
    finally:
        await websocket.close()


@app.websocket("/ws/d2z-metrics")
async def websocket_d2z_metrics(websocket):
    """WebSocket: D2Z指标实时推送"""
    await websocket.accept()
    
    try:
        while True:
            # 每2秒推送一次指标
            await asyncio.sleep(2)
            
            log_service.load_logs()
            metrics = log_service.get_metrics()
            
            await websocket.send_json({
                "type": "metrics_update",
                "data": metrics
            })
    
    except Exception as e:
        print(f"[WS] Connection error: {e}")
    finally:
        await websocket.close()


# ============================================================
# 根路由
# ============================================================

@app.get("/")
async def root():
    """根端点"""
    return {
        "name": config.APP_NAME,
        "version": config.APP_VERSION,
        "api_prefix": config.API_V1_PREFIX,
        "endpoints": {
            "health": f"{config.API_V1_PREFIX}/health",
            "events": f"{config.API_V1_PREFIX}/events",
            "metrics": f"{config.API_V1_PREFIX}/metrics",
            "websocket_events": "/ws/d2z-events",
            "websocket_metrics": "/ws/d2z-metrics",
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=config.DEBUG
    )