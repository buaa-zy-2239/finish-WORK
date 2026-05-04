"""
异常处理模块 - 统一异常定义和处理
"""

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from typing import Callable, Any
import logging

logger = logging.getLogger(__name__)


class SimulationError(Exception):
    """仿真服务异常基类"""
    def __init__(self, message: str, code: int = 500):
        super().__init__(message)
        self.message = message
        self.code = code


class TaskNotFoundError(SimulationError):
    """任务未找到异常"""
    def __init__(self, task_id: str):
        super().__init__(f"任务 {task_id} 不存在", 404)


class ConfigFileNotFoundError(SimulationError):
    """配置文件未找到异常"""
    def __init__(self, config_file: str):
        super().__init__(f"配置文件不存在: {config_file}", 404)


class SimulationTimeoutError(SimulationError):
    """仿真超时异常"""
    def __init__(self, task_id: str):
        super().__init__(f"仿真任务 {task_id} 执行超时", 504)


class InvalidTaskIdError(SimulationError):
    """无效任务ID异常"""
    def __init__(self, task_id: str):
        super().__init__(f"无效的任务ID格式: {task_id}", 400)


class ProtocolNotSupportedError(SimulationError):
    """不支持的协议异常"""
    def __init__(self, protocol: str):
        super().__init__(f"不支持的协议: {protocol}", 400)


class LogServiceError(SimulationError):
    """日志服务异常"""
    def __init__(self, message: str):
        super().__init__(f"日志服务错误: {message}", 500)


async def exception_handler(request: Request, exc: SimulationError) -> JSONResponse:
    """统一异常处理器"""
    logger.error(f"Exception occurred: {exc.message}")
    return JSONResponse(
        status_code=exc.code,
        content={
            "success": False,
            "error": exc.message,
            "code": exc.code,
            "path": request.url.path
        }
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """通用异常处理器"""
    logger.error(f"Unexpected error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "服务器内部错误",
            "code": 500,
            "path": request.url.path
        }
    )


def handle_exceptions(func: Callable[..., Any]) -> Callable[..., Any]:
    """装饰器：统一异常处理"""
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except SimulationError as e:
            raise HTTPException(status_code=e.code, detail=e.message)
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
    return wrapper