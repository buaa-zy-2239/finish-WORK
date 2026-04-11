# Backend/api/routes/health.py
"""
健康检查路由 - 应用状态监控
"""

from fastapi import APIRouter
from datetime import datetime
import os

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check():
    """
    健康检查端点
    
    Returns:
        dict: 应用健康状态信息
    """
    return {
        "status": "healthy",
        "service": "UAV D2Z Authentication Simulation Platform",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "uptime_info": "Running normally"
    }


@router.get("/status")
async def detailed_status():
    """
    获取详细的系统状态信息
    
    Returns:
        dict: 详细的系统状态
    """
    return {
        "status": "operational",
        "service_name": "UAV D2Z Backend API",
        "api_version": "v1",
        "python_version": "3.8+",
        "framework": "FastAPI",
        "timestamp": datetime.now().isoformat(),
        "environment": os.getenv("ENV", "development"),
        "features": {
            "simulation": True,
            "analysis": True,
            "websocket": True,
            "real_time_metrics": True
        }
    }


@router.get("/ready")
async def readiness_check():
    """
    就绪检查 - 用于Kubernetes健康探针
    
    Returns:
        dict: 就绪状态
    """
    return {
        "ready": True,
        "message": "Service is ready to accept requests",
        "timestamp": datetime.now().isoformat()
    }


@router.get("/live")
async def liveness_check():
    """
    存活性检查 - 用于Kubernetes健康探针
    
    Returns:
        dict: 存活状态
    """
    return {
        "alive": True,
        "message": "Service is alive and responsive",
        "timestamp": datetime.now().isoformat()
    }