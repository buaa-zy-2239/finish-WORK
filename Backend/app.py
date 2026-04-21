# Backend/app.py
"""
FastAPI 主应用 - 集成所有路由
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import sys
import os

# 添加Backend目录和项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import config
from services.log_service import log_service

# 导入路由模块
from api.routes import health, events, metrics, simulation, analysis

# 设置日志服务到路由模块
events.set_log_service(log_service)
metrics.set_log_service(log_service)


def create_app():
    """创建FastAPI应用"""
    
    app = FastAPI(
        title=config.APP_NAME,
        version=config.APP_VERSION,
        description="UAV D2Z Authentication Simulation Platform",
        debug=config.DEBUG,
    )

    # CORS 中间件
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
    app.include_router(simulation.router, prefix=config.API_V1_PREFIX)
    app.include_router(analysis.router, prefix=config.API_V1_PREFIX)

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
    # WebSocket - 实时数据推送
    # ============================================================

    @app.websocket("/ws/d2z-events")
    async def websocket_d2z_events(websocket):
        """WebSocket: D2Z事件实时推送"""
        await websocket.accept()
        
        last_event_count = len(log_service.events)
        
        try:
            while True:
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
                await asyncio.sleep(2)
                
                log_service.load_logs()
                metrics_data = log_service.get_metrics()
                
                await websocket.send_json({
                    "type": "metrics_update",
                    "data": metrics_data
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
            "description": "UAV D2Z Authentication Protocol Simulation Platform",
            "api_v1_prefix": config.API_V1_PREFIX,
            "endpoints": {
                "health": f"{config.API_V1_PREFIX}/health",
                "simulation": {
                    "create": f"{config.API_V1_PREFIX}/simulation/create",
                    "run": f"{config.API_V1_PREFIX}/simulation/run/{{task_id}}",
                    "status": f"{config.API_V1_PREFIX}/simulation/status/{{task_id}}",
                    "list": f"{config.API_V1_PREFIX}/simulation/list"
                },
                "analysis": {
                    "events": f"{config.API_V1_PREFIX}/analysis/events",
                    "metrics": f"{config.API_V1_PREFIX}/analysis/metrics",
                    "sessions": f"{config.API_V1_PREFIX}/analysis/sessions"
                },
                "websocket": {
                    "events": "/ws/d2z-events",
                    "metrics": "/ws/d2z-metrics"
                }
            }
        }

    return app


# 创建应用实例
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "Backend.app:app",
        host="0.0.0.0",
        port=8000,
        reload=config.DEBUG
    )