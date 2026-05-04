"""
移动模型基础工具模块 - 提供通用的移动模型辅助函数
"""

import math
from typing import List, Tuple, Any


class MobilityHelper:
    """移动模型辅助类 - 封装ns-3移动模型操作"""

    @staticmethod
    def create_container(node) -> Any:
        """创建包含单个节点的NodeContainer"""
        from ns import ns
        container = ns.NodeContainer()
        container.Add(node)
        return container

    @staticmethod
    def install_waypoint_model(node, waypoints: List[Tuple[float, List[float]]]) -> None:
        """安装Waypoint移动模型"""
        from ns import ns
        
        helper = ns.MobilityHelper()
        helper.SetMobilityModel("ns3::WaypointMobilityModel")
        
        container = MobilityHelper.create_container(node)
        helper.Install(container)
        
        mobility = node.GetObject[ns.WaypointMobilityModel]()
        
        for t, pos in waypoints:
            mobility.AddWaypoint(
                ns.Waypoint(
                    ns.Seconds(t),
                    ns.Vector(pos[0], pos[1], pos[2])
                )
            )

    @staticmethod
    def install_constant_position(node, position: List[float]) -> None:
        """安装固定位置模型（用于ZSP）"""
        from ns import ns
        
        helper = ns.MobilityHelper()
        helper.SetMobilityModel("ns3::ConstantPositionMobilityModel")
        
        container = MobilityHelper.create_container(node)
        helper.Install(container)
        
        mobility = node.GetObject[ns.MobilityModel]()
        mobility.SetPosition(ns.Vector(position[0], position[1], position[2]))

    @staticmethod
    def install_random_walk(node, bounds: Tuple[float, float, float, float] = (-500, 500, -500, 500)) -> None:
        """安装随机游走模型"""
        from ns import ns
        
        helper = ns.MobilityHelper()
        helper.SetMobilityModel(
            "ns3::RandomWalk2dMobilityModel",
            "Bounds", ns.RectangleValue(ns.Rectangle(*bounds))
        )
        
        container = MobilityHelper.create_container(node)
        helper.Install(container)


def calculate_travel_time(start: List[float], end: List[float], speed_mps: float) -> float:
    """计算两点之间的旅行时间"""
    dx = float(end[0]) - float(start[0])
    dy = float(end[1]) - float(start[1])
    dz = float(end[2]) - float(start[2])
    dist = math.sqrt(dx * dx + dy * dy + dz * dz)
    speed = max(float(speed_mps), 0.1)
    return dist / speed