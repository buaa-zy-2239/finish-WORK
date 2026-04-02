# Backend/api/routes/__init__.py
"""路由模块"""
from . import events, metrics, health

__all__ = ["events", "metrics", "health"]