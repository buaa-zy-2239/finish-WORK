"""
Simulator模块 - 提供仿真构建和会话跟踪功能

注意：simulator_builder需要ns-3环境，使用ns3 run命令运行
"""

from .session_record import SessionRecord
from .metrics_collector import MetricsCollector
from .session_tracker import SessionTracker
from .network_config import NetworkConfigurator
from .channel_models import ChannelModelFactory


def get_simulation_builder():
    """延迟导入SimulationBuilderEnhanced（需要ns-3环境）"""
    from .simulator_builder import SimulationBuilderEnhanced
    return SimulationBuilderEnhanced


__all__ = [
    "SessionRecord",
    "MetricsCollector",
    "SessionTracker",
    "NetworkConfigurator",
    "ChannelModelFactory",
    "get_simulation_builder",
]