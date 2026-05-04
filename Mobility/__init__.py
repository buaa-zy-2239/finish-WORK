"""
Mobility模块 - 提供UAV移动模型实现

注意：需要ns-3环境，使用ns3 run命令运行
"""

from .base import MobilityHelper, calculate_travel_time
from .waypoint_builder import WaypointBuilder
from .gauss_markov import GaussMarkovMobility
from .mobility import MobilityFactory


__all__ = [
    "MobilityFactory",
    "MobilityHelper",
    "WaypointBuilder",
    "GaussMarkovMobility",
    "calculate_travel_time",
]