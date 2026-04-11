# Backend/api/routes/metrics.py
"""
指标查询路由 - 提供D2Z协议性能指标
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from datetime import datetime

router = APIRouter(prefix="/metrics", tags=["metrics"])

# 全局变量，由app.py设置
log_service = None


def set_log_service(service):
    """设置日志服务"""
    global log_service
    log_service = service


@router.get("/summary")
async def get_metrics_summary() -> dict:
    """获取D2Z协议性能指标摘要"""
    try:
        metrics = log_service.get_metrics()
        
        return {
            "success": True,
            "metrics": metrics,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve metrics: {str(e)}"
        )


@router.get("/authentication")
async def get_authentication_metrics() -> dict:
    """获取认证相关指标"""
    try:
        metrics = log_service.get_metrics()
        auth_metrics = metrics.get("authentication", {})
        
        return {
            "success": True,
            "authentication": {
                "total_sessions": auth_metrics.get("total_sessions", 0),
                "successful_sessions": auth_metrics.get("successful", 0),
                "failed_sessions": auth_metrics.get("failed", 0),
                "success_rate_percent": auth_metrics.get("success_rate_percent", 0.0),
                "failure_rate_percent": 100.0 - auth_metrics.get("success_rate_percent", 0.0)
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve authentication metrics: {str(e)}"
        )


@router.get("/messaging")
async def get_messaging_metrics() -> dict:
    """获取消息相关指标"""
    try:
        metrics = log_service.get_metrics()
        msg_metrics = metrics.get("messaging", {})
        
        return {
            "success": True,
            "messaging": {
                "total_messages": msg_metrics.get("total_messages", 0),
                "average_message_size_bytes": msg_metrics.get("avg_size_bytes", 0.0),
                "total_bytes_transmitted": msg_metrics.get("total_bytes", 0),
                "total_kilobytes": msg_metrics.get("total_bytes", 0) / 1024
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve messaging metrics: {str(e)}"
        )


@router.get("/timing")
async def get_timing_metrics() -> dict:
    """获取时间相关指标"""
    try:
        metrics = log_service.get_metrics()
        timing_metrics = metrics.get("timing", {})
        
        return {
            "success": True,
            "timing": {
                "average_duration_seconds": timing_metrics.get("avg_duration_seconds", 0.0),
                "minimum_duration_seconds": timing_metrics.get("min_duration_seconds", 0.0),
                "maximum_duration_seconds": timing_metrics.get("max_duration_seconds", 0.0),
                "average_duration_milliseconds": timing_metrics.get("avg_duration_seconds", 0.0) * 1000,
                "minimum_duration_milliseconds": timing_metrics.get("min_duration_seconds", 0.0) * 1000,
                "maximum_duration_milliseconds": timing_metrics.get("max_duration_seconds", 0.0) * 1000
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve timing metrics: {str(e)}"
        )


@router.get("/errors")
async def get_error_metrics() -> dict:
    """获取错误相关指标"""
    try:
        metrics = log_service.get_metrics()
        error_metrics = metrics.get("errors", {})
        
        return {
            "success": True,
            "errors": {
                "total_errors": error_metrics.get("total", 0),
                "M1_errors": error_metrics.get("M1_errors", 0),
                "M2_errors": error_metrics.get("M2_errors", 0),
                "M3_M4_errors": error_metrics.get("M3_M4_errors", 0)
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve error metrics: {str(e)}"
        )


@router.get("/performance")
async def get_performance_metrics() -> dict:
    """获取综合性能指标"""
    try:
        metrics = log_service.get_metrics()
        
        auth = metrics.get("authentication", {})
        msg = metrics.get("messaging", {})
        timing = metrics.get("timing", {})
        
        return {
            "success": True,
            "performance": {
                "success_rate": f"{auth.get('success_rate_percent', 0):.2f}%",
                "communication_efficiency": {
                    "total_messages": msg.get("total_messages", 0),
                    "average_message_size_kb": msg.get("avg_size_bytes", 0) / 1024,
                    "total_data_transmitted_kb": msg.get("total_bytes", 0) / 1024
                },
                "authentication_performance": {
                    "average_time_seconds": f"{timing.get('avg_duration_seconds', 0):.4f}",
                    "average_time_milliseconds": f"{timing.get('avg_duration_seconds', 0) * 1000:.2f}"
                }
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve performance metrics: {str(e)}"
        )


@router.get("/comparison")
async def get_comparison_metrics(
    metric1: str = Query("success_rate", description="第一个指标"),
    metric2: str = Query("avg_duration", description="第二个指标"),
) -> dict:
    """获取指标对比信息"""
    try:
        metrics = log_service.get_metrics()
        
        return {
            "success": True,
            "comparison": {
                metric1: _extract_metric(metrics, metric1),
                metric2: _extract_metric(metrics, metric2)
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve comparison metrics: {str(e)}"
        )


@router.get("/status")
async def get_metrics_status() -> dict:
    """获取指标系统状态"""
    try:
        status = log_service.get_log_status()
        
        return {
            "success": True,
            "status": {
                "log_directory": status.get("log_directory"),
                "total_events_loaded": status.get("total_events"),
                "total_sessions_analyzed": status.get("sessions"),
                "last_update_timestamp": status.get("last_update"),
                "is_fresh": (datetime.now().timestamp() - status.get("last_update", 0)) < 60
            },
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve metrics status: {str(e)}"
        )


@router.get("/export")
async def export_all_metrics(
    format: str = Query("json", pattern="^(json|csv)$", description="导出格式")
) -> dict:
    """导出所有指标数据"""
    try:
        metrics = log_service.get_metrics()
        
        return {
            "success": True,
            "format": format,
            "metrics": metrics,
            "export_timestamp": datetime.now().isoformat(),
            "note": "导出时间戳反映数据的最后更新时间"
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export metrics: {str(e)}"
        )


def _extract_metric(metrics: dict, metric_name: str):
    """从指标字典中提取指定指标"""
    mapping = {
        "success_rate": lambda m: m.get("authentication", {}).get("success_rate_percent"),
        "total_sessions": lambda m: m.get("authentication", {}).get("total_sessions"),
        "successful_sessions": lambda m: m.get("authentication", {}).get("successful"),
        "failed_sessions": lambda m: m.get("authentication", {}).get("failed"),
        "total_messages": lambda m: m.get("messaging", {}).get("total_messages"),
        "avg_message_size": lambda m: m.get("messaging", {}).get("avg_size_bytes"),
        "total_bytes": lambda m: m.get("messaging", {}).get("total_bytes"),
        "avg_duration": lambda m: m.get("timing", {}).get("avg_duration_seconds"),
        "min_duration": lambda m: m.get("timing", {}).get("min_duration_seconds"),
        "max_duration": lambda m: m.get("timing", {}).get("max_duration_seconds"),
        "total_errors": lambda m: m.get("errors", {}).get("total"),
    }
    
    extractor = mapping.get(metric_name)
    if extractor:
        return extractor(metrics)
    return None