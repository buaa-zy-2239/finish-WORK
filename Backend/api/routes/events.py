# Backend/api/routes/events.py
"""
事件查询路由 - 提供D2Z认证事件数据
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from datetime import datetime

# 不使用相对导入，而是在app.py中导入后传递
router = APIRouter(prefix="/events", tags=["events"])

# 全局变量，由app.py设置
log_service = None


def set_log_service(service):
    """设置日志服务"""
    global log_service
    log_service = service


@router.get("")
async def get_events(
    limit: int = Query(100, ge=1, le=1000, description="返回的最大事件数"),
    offset: int = Query(0, ge=0, description="偏移量"),
    uav_id: Optional[int] = Query(None, description="按UAV ID过滤"),
    zsp_id: Optional[int] = Query(None, description="按ZSP ID过滤"),
    phase: Optional[str] = Query(None, description="按认证阶段过滤"),
) -> dict:
    """
    获取D2Z认证事件列表（支持分页和过滤）
    
    Args:
        limit: 每页返回的事件数 (默认100，最大1000)
        offset: 分页偏移量 (默认0)
        uav_id: 过滤特定UAV的事件
        zsp_id: 过滤特定ZSP的事件
        phase: 过滤特定认证阶段的事件
    
    Returns:
        dict: 包含分页信息和事件列表
    """
    try:
        all_events = log_service.get_events(limit=10000)
        
        filtered_events = all_events
        
        if uav_id is not None:
            filtered_events = [e for e in filtered_events if e.get('uav_id') == uav_id]
        
        if zsp_id is not None:
            filtered_events = [e for e in filtered_events if e.get('zsp_id') == zsp_id]
        
        if phase is not None:
            filtered_events = [e for e in filtered_events if e.get('phase') == phase]
        
        paginated_events = filtered_events[offset:offset + limit]
        
        return {
            "success": True,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "total": len(filtered_events),
                "returned": len(paginated_events),
                "has_next": (offset + limit) < len(filtered_events)
            },
            "filters": {
                "uav_id": uav_id,
                "zsp_id": zsp_id,
                "phase": phase
            },
            "events": paginated_events,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve events: {str(e)}"
        )


@router.get("/count")
async def count_events(
    uav_id: Optional[int] = Query(None, description="按UAV ID过滤"),
    zsp_id: Optional[int] = Query(None, description="按ZSP ID过滤"),
    phase: Optional[str] = Query(None, description="按认证阶段过滤"),
) -> dict:
    """获取事件总数（支持过滤）"""
    try:
        all_events = log_service.get_events(limit=10000)
        
        filtered_events = all_events
        
        if uav_id is not None:
            filtered_events = [e for e in filtered_events if e.get('uav_id') == uav_id]
        
        if zsp_id is not None:
            filtered_events = [e for e in filtered_events if e.get('zsp_id') == zsp_id]
        
        if phase is not None:
            filtered_events = [e for e in filtered_events if e.get('phase') == phase]
        
        return {
            "success": True,
            "total": len(filtered_events),
            "filters": {
                "uav_id": uav_id,
                "zsp_id": zsp_id,
                "phase": phase
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to count events: {str(e)}"
        )


@router.get("/recent")
async def get_recent_events(
    limit: int = Query(50, ge=1, le=500, description="返回的最近事件数")
) -> dict:
    """获取最近的事件"""
    try:
        all_events = log_service.get_events(limit=limit)
        
        return {
            "success": True,
            "count": len(all_events),
            "events": all_events,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve recent events: {str(e)}"
        )


@router.get("/by-phase/{phase}")
async def get_events_by_phase(
    phase: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    """按认证阶段查询事件"""
    try:
        all_events = log_service.get_events(limit=10000)
        
        filtered_events = [e for e in all_events if e.get('phase') == phase]
        paginated_events = filtered_events[offset:offset + limit]
        
        return {
            "success": True,
            "phase": phase,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "total": len(filtered_events),
                "returned": len(paginated_events)
            },
            "events": paginated_events,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve events by phase: {str(e)}"
        )


@router.get("/by-uav/{uav_id}")
async def get_events_by_uav(
    uav_id: int,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    """按UAV ID查询事件"""
    try:
        all_events = log_service.get_events(limit=10000)
        
        filtered_events = [e for e in all_events if e.get('uav_id') == uav_id]
        paginated_events = filtered_events[offset:offset + limit]
        
        return {
            "success": True,
            "uav_id": uav_id,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "total": len(filtered_events),
                "returned": len(paginated_events)
            },
            "events": paginated_events,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve events for UAV {uav_id}: {str(e)}"
        )


@router.get("/by-zsp/{zsp_id}")
async def get_events_by_zsp(
    zsp_id: int,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict:
    """按ZSP ID查询事件"""
    try:
        all_events = log_service.get_events(limit=10000)
        
        filtered_events = [e for e in all_events if e.get('zsp_id') == zsp_id]
        paginated_events = filtered_events[offset:offset + limit]
        
        return {
            "success": True,
            "zsp_id": zsp_id,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "total": len(filtered_events),
                "returned": len(paginated_events)
            },
            "events": paginated_events,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve events for ZSP {zsp_id}: {str(e)}"
        )


@router.get("/statistics")
async def get_event_statistics() -> dict:
    """获取事件统计信息"""
    try:
        all_events = log_service.get_events(limit=10000)
        
        if not all_events:
            return {
                "success": True,
                "total_events": 0,
                "by_phase": {},
                "by_uav": {},
                "by_zsp": {},
                "timestamp": datetime.now().isoformat()
            }
        
        by_phase = {}
        by_uav = {}
        by_zsp = {}
        
        for event in all_events:
            phase = event.get('phase', 'unknown')
            uav_id = event.get('uav_id')
            zsp_id = event.get('zsp_id')
            
            by_phase[phase] = by_phase.get(phase, 0) + 1
            
            if uav_id is not None:
                by_uav[uav_id] = by_uav.get(uav_id, 0) + 1
            
            if zsp_id is not None:
                by_zsp[zsp_id] = by_zsp.get(zsp_id, 0) + 1
        
        return {
            "success": True,
            "total_events": len(all_events),
            "by_phase": by_phase,
            "by_uav": by_uav,
            "by_zsp": by_zsp,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get event statistics: {str(e)}"
        )