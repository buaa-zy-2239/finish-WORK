"""
移动模型工厂 - 提供统一的移动模型安装接口
"""

from typing import Dict, Any

from .base import MobilityHelper, calculate_travel_time
from .waypoint_builder import WaypointBuilder
from .gauss_markov import GaussMarkovMobility


class MobilityFactory:
    """移动模型工厂 - 统一的移动模型安装入口"""

    @staticmethod
    def install(node, mobility_conf: Dict[str, Any]) -> None:
        """
        根据配置安装移动模型

        Args:
            node: ns-3节点
            mobility_conf: 移动模型配置字典
        """
        mtype = mobility_conf["type"]

        if mtype == "waypoint":
            MobilityHelper.install_waypoint_model(node, mobility_conf["waypoints"])

        elif mtype == "random":
            MobilityHelper.install_random_walk(node)

        elif mtype == "trace":
            MobilityHelper.install_waypoint_model(node, mobility_conf["waypoints"])

        elif mtype == "patrol":
            waypoints = WaypointBuilder.build_patrol_waypoints(mobility_conf)
            MobilityHelper.install_waypoint_model(node, waypoints)

        elif mtype == "formation":
            waypoints = WaypointBuilder.build_formation_waypoints(mobility_conf)
            MobilityHelper.install_waypoint_model(node, waypoints)

        elif mtype == "transit":
            waypoints = WaypointBuilder.build_transit_waypoints(mobility_conf)
            MobilityHelper.install_waypoint_model(node, waypoints)

        elif mtype == "gauss_markov_3d":
            GaussMarkovMobility.install_ns3_native(node, mobility_conf)

        elif mtype == "ns3::GaussMarkovMobilityModel":
            GaussMarkovMobility.install_ns3_native(node, mobility_conf)

        else:
            raise ValueError(f"Unknown mobility type: {mtype}")

    @staticmethod
    def install_constant(node, pos) -> None:
        """
        安装固定位置模型（用于ZSP）

        Args:
            node: ns-3节点
            pos: 位置坐标 [x, y, z]
        """
        MobilityHelper.install_constant_position(node, pos)