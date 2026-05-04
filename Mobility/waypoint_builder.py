"""
航点构建器模块 - 提供各种移动模式的航点生成功能
"""

import math
from typing import List, Dict, Any, Tuple

from .base import calculate_travel_time


class WaypointBuilder:
    """航点构建器 - 生成各种移动模式的航点"""

    @staticmethod
    def build_patrol_waypoints(mobility_conf: Dict[str, Any]) -> List[Tuple[float, List[float]]]:
        """构建巡逻模式航点"""
        route = mobility_conf.get("route") or []
        dwell_s = float(mobility_conf.get("dwell_s", 2.0))
        speed_mps = float(mobility_conf.get("speed_mps", 18.0))
        
        if len(route) < 2:
            raise ValueError("patrol mobility requires at least two route points")

        waypoints = [[0.0, list(route[0])]]
        current_t = 0.0
        current = route[0]
        
        for idx in range(1, len(route)):
            nxt = route[idx]
            current_t += calculate_travel_time(current, nxt, speed_mps)
            waypoints.append([current_t, list(nxt)])
            if idx < len(route) - 1:
                current_t += dwell_s
                waypoints.append([current_t, list(nxt)])
            current = nxt
        
        return waypoints

    @staticmethod
    def build_formation_waypoints(mobility_conf: Dict[str, Any]) -> List[Tuple[float, List[float]]]:
        """构建编队模式航点"""
        anchor = mobility_conf.get("anchor_waypoints") or []
        offset = mobility_conf.get("offset", [0, 0, 0])
        
        if not anchor:
            raise ValueError("formation mobility requires anchor_waypoints")
        
        return [
            [
                float(t),
                [
                    float(pos[0]) + float(offset[0]),
                    float(pos[1]) + float(offset[1]),
                    float(pos[2]) + float(offset[2]),
                ],
            ]
            for t, pos in anchor
        ]

    @staticmethod
    def build_transit_waypoints(mobility_conf: Dict[str, Any]) -> List[Tuple[float, List[float]]]:
        """构建过境模式航点"""
        start = mobility_conf.get("start")
        end = mobility_conf.get("end")
        speed_mps = float(mobility_conf.get("speed_mps", 35.0))
        
        if start is None or end is None:
            raise ValueError("transit mobility requires start and end")
        
        duration = calculate_travel_time(start, end, speed_mps)
        
        waypoints = []
        step_time = 0.1
        num_waypoints = max(int(duration / step_time), 1000)
        duration = num_waypoints * step_time
        
        for i in range(num_waypoints + 1):
            t = i * step_time
            progress = min(t / duration, 1.0)
            pos = [
                start[0] + (end[0] - start[0]) * progress,
                start[1] + (end[1] - start[1]) * progress,
                start[2] + (end[2] - start[2]) * progress
            ]
            waypoints.append([t, pos])
        
        return waypoints

    @staticmethod
    def interpolate_waypoints(
        start: List[float], 
        end: List[float], 
        duration: float,
        num_points: int
    ) -> List[Tuple[float, List[float]]]:
        """线性插值生成航点"""
        waypoints = []
        step_time = duration / num_points
        
        for i in range(num_points + 1):
            t = i * step_time
            progress = t / duration
            pos = [
                start[0] + (end[0] - start[0]) * progress,
                start[1] + (end[1] - start[1]) * progress,
                start[2] + (end[2] - start[2]) * progress
            ]
            waypoints.append([t, pos])
        
        return waypoints