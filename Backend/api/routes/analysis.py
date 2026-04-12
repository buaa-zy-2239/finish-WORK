# Backend/api/routes/analysis.py
"""
分析结果路由 - 提供日志分析和可视化数据
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Dict, Optional

from services.log_service import log_service

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.get("/events")
async def get_events(
    limit: int = 100,
    task_id: Optional[str] = Query(None, description="仿真任务 ID，从任务目录 logs/ 读取"),
) -> Dict:
    """
    获取D2Z认证事件列表
    
    Args:
        limit: 返回的最大事件数
    """
    try:
        events = log_service.get_events(limit=limit, task_id=task_id)
        return {
            "success": True,
            "total": len(events),
            "events": events
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/metrics")
async def get_metrics(task_id: Optional[str] = Query(None)) -> Dict:
    """获取D2Z协议性能指标"""
    try:
        metrics = log_service.get_metrics(task_id=task_id)
        return {
            "success": True,
            "metrics": metrics
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/sessions")
async def get_sessions(task_id: Optional[str] = Query(None)) -> Dict:
    """获取所有D2Z认证会话"""
    try:
        sessions = log_service.get_sessions(task_id=task_id)
        return {
            "success": True,
            "total": len(sessions),
            "sessions": sessions
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/sessions/{uav_id}/{zsp_id}/timeline")
async def get_session_timeline(
    uav_id: int,
    zsp_id: int,
    session_id: Optional[str] = Query(None, description="会话 ID（auth_session_id 或 session_id）"),
    task_id: Optional[str] = Query(None),
) -> Dict:
    """获取特定会话的事件时间线"""
    try:
        timeline = log_service.get_session_timeline(
            uav_id, zsp_id, session_id=session_id, task_id=task_id
        )
        return {
            "success": True,
            "uav_id": uav_id,
            "zsp_id": zsp_id,
            "total_events": len(timeline),
            "timeline": timeline
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/uav/{uav_id}/stats")
async def get_uav_statistics(uav_id: int, task_id: Optional[str] = Query(None)) -> Dict:
    """获取UAV的D2Z认证统计"""
    try:
        stats = log_service.get_uav_stats(uav_id, task_id=task_id)
        return {
            "success": True,
            "stats": stats
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/status")
async def get_analysis_status(task_id: Optional[str] = Query(None)) -> Dict:
    """获取日志分析系统状态"""
    try:
        status = log_service.get_log_status(task_id=task_id)
        return {
            "success": True,
            "status": status
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/export/json")
async def export_as_json(task_id: Optional[str] = Query(None)) -> Dict:
    """导出完整分析结果为JSON"""
    try:
        data = {
            "metrics": log_service.get_metrics(task_id=task_id),
            "sessions": log_service.get_sessions(task_id=task_id),
            "status": log_service.get_log_status(task_id=task_id),
        }
        return {
            "success": True,
            "data": data
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))