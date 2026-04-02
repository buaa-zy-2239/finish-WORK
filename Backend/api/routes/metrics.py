# Backend/api/routes/metrics.py
"""
指标相关API路由
"""

from fastapi import APIRouter, HTTPException

from ...services.log_service import log_service

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/d2z-summary")
async def get_d2z_summary():
    """获取D2Z认证流程总体指标"""
    try:
        metrics = log_service.get_metrics()
        return metrics
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions")
async def get_all_sessions():
    """获取所有D2Z会话"""
    try:
        sessions = log_service.get_sessions()
        return {
            "total_sessions": len(sessions),
            "sessions": sessions
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/uav/{uav_id}")
async def get_uav_stats(uav_id: int):
    """获取UAV的D2Z统计"""
    try:
        stats = log_service.get_uav_stats(uav_id)
        
        if not stats or stats.get("total_sessions", 0) == 0:
            raise HTTPException(status_code=404, detail=f"No data for UAV-{uav_id}")
        
        return stats
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))