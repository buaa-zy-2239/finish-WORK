# Backend/api/routes/health.py
"""
健康检查API
"""

from fastapi import APIRouter

from ...services.log_service import log_service

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check():
    """系统健康检查"""
    status_info = log_service.get_log_status()
    
    return {
        "status": "healthy" if status_info["total_events"] > 0 else "no_data",
        "log_info": status_info
    }