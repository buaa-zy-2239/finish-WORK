# Backend/api/routes/events.py
"""
事件相关API路由
"""

from fastapi import APIRouter, Query, HTTPException
from typing import List

from ...services.log_service import log_service

router = APIRouter(prefix="/events", tags=["events"])


@router.get("/latest")
async def get_latest_events(limit: int = Query(100, ge=1, le=1000)):
    """获取最新事件"""
    try:
        events = log_service.get_events(limit=limit)
        return {
            "count": len(events),
            "events": events
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/timeline/{uav_id}/{zsp_id}")
async def get_session_timeline(uav_id: int, zsp_id: int):
    """获取D2Z会话的事件时间线"""
    try:
        timeline = log_service.get_session_timeline(uav_id, zsp_id)
        
        if not timeline:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return {
            "uav_id": uav_id,
            "zsp_id": zsp_id,
            "event_count": len(timeline),
            "events": timeline
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))