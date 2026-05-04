"""
Gauss-Markov移动模型模块 - 实现IEEE TWC/INFOCOM标准的3D移动模型
"""

import math
import random
from typing import Dict, Any, List, Tuple


class GaussMarkovMobility:
    """Gauss-Markov 3D移动模型 (IEEE TWC/INFOCOM标准)"""

    DEFAULT_PARAMS = {
        "alpha": 0.8,
        "speed_mean": 15.0,
        "speed_std": 5.0,
        "area_size": 1000.0,
        "altitude_range": 200.0,
        "duration": 60.0,
        "time_step": 1.0,
        "seed": 42,
    }

    @staticmethod
    def generate_waypoints(node_id: int, mobility_conf: Dict[str, Any]) -> List[Tuple[float, List[float]]]:
        """
        生成Gauss-Markov 3D轨迹航点
        """
        params = {**GaussMarkovMobility.DEFAULT_PARAMS, **mobility_conf}
        
        alpha = float(params["alpha"])
        speed_mean = float(params["speed_mean"])
        speed_std = float(params["speed_std"])
        area_size = float(params["area_size"])
        altitude_range = float(params["altitude_range"])
        duration = float(params["duration"])
        time_step = float(params["time_step"])
        seed = int(params["seed"])

        rng = random.Random(seed + node_id)

        initial_position = mobility_conf.get("initial_position")
        if initial_position:
            x, y, z = float(initial_position[0]), float(initial_position[1]), float(initial_position[2])
        else:
            x = rng.uniform(-area_size / 2, area_size / 2)
            y = rng.uniform(-area_size / 2, area_size / 2)
            z = rng.uniform(50, 50 + altitude_range)
        pos = [x, y, z]

        initial_velocity = mobility_conf.get("initial_velocity")
        if initial_velocity:
            vx = float(initial_velocity[0])
            vy = float(initial_velocity[1])
            vz = float(initial_velocity[2])
            speed = math.sqrt(vx * vx + vy * vy + vz * vz)
            if speed > 0:
                theta = math.atan2(vy, vx)
                phi = math.atan2(math.sqrt(vx * vx + vy * vy), vz)
            else:
                theta = rng.uniform(0, 2 * math.pi)
                phi = rng.uniform(0, math.pi)
        else:
            speed = max(rng.gauss(speed_mean, speed_std), 5.0)
            theta = rng.uniform(0, 2 * math.pi)
            phi = rng.uniform(0, math.pi)
            vx = speed * math.sin(phi) * math.cos(theta)
            vy = speed * math.sin(phi) * math.sin(theta)
            vz = speed * math.cos(phi)

        waypoints = [[0.0, list(pos)]]
        t = 0.0

        while t < duration:
            t += time_step

            speed_old = math.sqrt(vx * vx + vy * vy + vz * vz)

            speed_new = (
                alpha * speed_old +
                (1 - alpha) * speed_mean +
                math.sqrt(1 - alpha * alpha) * rng.gauss(0, speed_std)
            )
            speed_new = max(speed_new, 5.0)

            theta_change = rng.gauss(0, (1 - alpha) * math.pi / 4)
            theta = theta * alpha + theta_change

            phi_change = rng.gauss(0, (1 - alpha) * math.pi / 8)
            phi = phi * alpha + phi_change
            phi = max(math.pi / 6, min(5 * math.pi / 6, phi))

            vx = speed_new * math.sin(phi) * math.cos(theta)
            vy = speed_new * math.sin(phi) * math.sin(theta)
            vz = speed_new * math.cos(phi)

            pos[0] += vx * time_step
            pos[1] += vy * time_step
            pos[2] += vz * time_step

            if abs(pos[0]) > area_size / 2:
                pos[0] = math.copysign(area_size / 2 - 10, pos[0])
                vx = -vx
                theta = math.atan2(vy, vx)
            if abs(pos[1]) > area_size / 2:
                pos[1] = math.copysign(area_size / 2 - 10, pos[1])
                vy = -vy
                theta = math.atan2(vy, vx)
            if pos[2] < 30 or pos[2] > 50 + altitude_range:
                pos[2] = max(30, min(50 + altitude_range, pos[2]))
                vz = -vz
                phi = math.atan2(math.sqrt(vx * vx + vy * vy), vz)

            waypoints.append([round(t, 2), [round(pos[0], 2), round(pos[1], 2), round(pos[2], 2)]])

        return waypoints

    @staticmethod
    def install_ns3_native(node, mobility_conf: Dict[str, Any]) -> None:
        """使用ns-3内置的GaussMarkovMobilityModel"""
        from ns import ns
        
        helper = ns.MobilityHelper()

        if "Bounds" in mobility_conf:
            bounds_str = mobility_conf["Bounds"]
            bounds_values = [float(x.strip()) for x in bounds_str.split(",")]
            if len(bounds_values) != 6:
                raise ValueError(f"Bounds must have 6 values, got {len(bounds_values)}")
            bounds = ns.Box(*bounds_values)
        else:
            area_size_x = float(mobility_conf.get("area_size_x", mobility_conf.get("area_size", 600)))
            area_size_y = float(mobility_conf.get("area_size_y", area_size_x))
            min_alt = float(mobility_conf.get("min_altitude_m", 30))
            max_alt = float(mobility_conf.get("max_altitude_m", 200))
            bounds = ns.Box(0, area_size_x, 0, area_size_y, min_alt, max_alt)

        time_step_val = mobility_conf.get("TimeStep", mobility_conf.get("time_step", 0.1))
        if isinstance(time_step_val, str) and time_step_val.endswith("s"):
            time_step_val = float(time_step_val[:-1])
        time_step_val = float(time_step_val)

        alpha_val = float(mobility_conf.get("Alpha", mobility_conf.get("alpha", 0.7)))

        mean_speed = float(mobility_conf.get("mean_speed_mps", 5.0))
        speed_std = float(mobility_conf.get("speed_std_mps", 5.0))
        min_speed = max(0.1, mean_speed - speed_std)
        max_speed = mean_speed + speed_std

        mean_velocity = mobility_conf.get(
            "MeanVelocity",
            f"ns3::UniformRandomVariable[Min={min_speed:.2f}|Max={max_speed:.2f}]"
        )

        normal_velocity_var = mobility_conf.get(
            "NormalVelocity",
            f"ns3::NormalRandomVariable[Mean=0.0|Variance={speed_std * speed_std:.2f}|Bound={speed_std * 2:.2f}]"
        )

        mean_pitch = mobility_conf.get("MeanPitch", "ns3::UniformRandomVariable[Min=-0.2|Max=0.2]")
        normal_pitch = mobility_conf.get("NormalPitch", "ns3::NormalRandomVariable[Mean=0.0|Variance=0.1|Bound=0.3]")

        helper.SetMobilityModel(
            "ns3::GaussMarkovMobilityModel",
            "Bounds", ns.BoxValue(bounds),
            "TimeStep", ns.TimeValue(ns.Seconds(time_step_val)),
            "Alpha", ns.DoubleValue(alpha_val),
            "MeanVelocity", ns.StringValue(mean_velocity),
            "MeanDirection", ns.StringValue(mobility_conf.get("MeanDirection", "ns3::UniformRandomVariable[Min=0|Max=6.283185307]")),
            "MeanPitch", ns.StringValue(mean_pitch),
            "NormalVelocity", ns.StringValue(normal_velocity_var),
            "NormalDirection", ns.StringValue(mobility_conf.get("NormalDirection", "ns3::NormalRandomVariable[Mean=0.0|Variance=0.2|Bound=0.4]")),
            "NormalPitch", ns.StringValue(normal_pitch),
        )

        # 暂时使用随机位置，避免复杂的兼容性问题
        helper.SetPositionAllocator(
            "ns3::RandomBoxPositionAllocator",
            "X", ns.StringValue(f"ns3::UniformRandomVariable[Min={bounds.xMin}|Max={bounds.xMax}]"),
            "Y", ns.StringValue(f"ns3::UniformRandomVariable[Min={bounds.yMin}|Max={bounds.yMax}]"),
            "Z", ns.StringValue(f"ns3::UniformRandomVariable[Min={bounds.zMin}|Max={bounds.zMax}]")
        )

        container = ns.NodeContainer()
        container.Add(node)
        helper.Install(container)
