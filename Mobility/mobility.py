from ns import ns


class MobilityFactory:

    # =========================
    # 通用入口
    # =========================

    @staticmethod
    def install(node, mobility_conf):
        mtype = mobility_conf["type"]

        if mtype == "waypoint":
            MobilityFactory._install_waypoint(
                node,
                mobility_conf["waypoints"]
            )

        elif mtype == "random":
            MobilityFactory._install_random(node)

        elif mtype == "trace":
            MobilityFactory._install_waypoint(
                node,
                mobility_conf["waypoints"]
            )

        elif mtype == "patrol":
            MobilityFactory._install_waypoint(
                node,
                MobilityFactory._build_patrol_waypoints(mobility_conf)
            )

        elif mtype == "formation":
            MobilityFactory._install_waypoint(
                node,
                MobilityFactory._build_formation_waypoints(mobility_conf)
            )

        elif mtype == "transit":
            MobilityFactory._install_waypoint(
                node,
                MobilityFactory._build_transit_waypoints(mobility_conf)
            )

        elif mtype == "gauss_markov_3d":
            MobilityFactory._install_gauss_markov_3d(node, mobility_conf)

        else:
            raise ValueError(f"Unknown mobility type: {mtype}")

    # =========================
    # Waypoint
    # =========================

    @staticmethod
    def _install_waypoint(node, waypoints):

        helper = ns.MobilityHelper()
        helper.SetMobilityModel("ns3::WaypointMobilityModel")

        container = ns.NodeContainer()
        container.Add(node)

        helper.Install(container)

        mobility = node.GetObject[ns.WaypointMobilityModel]()

        for t, pos in waypoints:

            mobility.AddWaypoint(
                ns.Waypoint(
                    ns.Seconds(t),
                    ns.Vector(pos[0], pos[1], pos[2])
                )
            )

    # =========================
    # Random
    # =========================

    @staticmethod
    def _install_random(node):

        helper = ns.MobilityHelper()

        helper.SetMobilityModel(
            "ns3::RandomWalk2dMobilityModel",
            "Bounds", ns.RectangleValue(ns.Rectangle(-500, 500, -500, 500))
        )

        container = ns.NodeContainer()
        container.Add(node)

        helper.Install(container)

    # =========================
    # ZSP固定位置
    # =========================

    @staticmethod
    def install_constant(node, pos):

        helper = ns.MobilityHelper()

        helper.SetMobilityModel("ns3::ConstantPositionMobilityModel")

        container = ns.NodeContainer()
        container.Add(node)

        helper.Install(container)

        mobility = node.GetObject[ns.MobilityModel]()

        mobility.SetPosition(
            ns.Vector(pos[0], pos[1], pos[2])
        )

    @staticmethod
    def _build_patrol_waypoints(mobility_conf):
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
            current_t += MobilityFactory._travel_time(current, nxt, speed_mps)
            waypoints.append([current_t, list(nxt)])
            if idx < len(route) - 1:
                current_t += dwell_s
                waypoints.append([current_t, list(nxt)])
            current = nxt
        return waypoints

    @staticmethod
    def _build_formation_waypoints(mobility_conf):
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
    def _build_transit_waypoints(mobility_conf):
        start = mobility_conf.get("start")
        end = mobility_conf.get("end")
        speed_mps = float(mobility_conf.get("speed_mps", 35.0))
        if start is None or end is None:
            raise ValueError("transit mobility requires start and end")
        duration = MobilityFactory._travel_time(start, end, speed_mps)
        return [[0.0, list(start)], [duration, list(end)]]

    @staticmethod
    def _travel_time(start, end, speed_mps):
        dx = float(end[0]) - float(start[0])
        dy = float(end[1]) - float(start[1])
        dz = float(end[2]) - float(start[2])
        dist = (dx * dx + dy * dy + dz * dz) ** 0.5
        speed = max(float(speed_mps), 0.1)
        return dist / speed

    # =========================
    # Gauss-Markov 3D (顶会标准)
    # =========================

    @staticmethod
    def _install_gauss_markov_3d(node, mobility_conf):
        """
        Gauss-Markov 3D移动模型 (IEEE TWC/INFOCOM标准)

        参数:
        - alpha: 记忆因子 (0-1)，0.8表示80%保持原方向
        - speed_mean: 平均速度 (m/s)
        - speed_std: 速度标准差
        - area_size: 水平活动范围 (m)
        - altitude_range: 垂直活动范围 (m)
        - duration: 仿真时长 (s)
        - time_step: 轨迹采样间隔 (s)
        """
        import random
        import math

        alpha = float(mobility_conf.get("alpha", 0.8))
        speed_mean = float(mobility_conf.get("speed_mean", 15.0))
        speed_std = float(mobility_conf.get("speed_std", 5.0))
        area_size = float(mobility_conf.get("area_size", 1000.0))
        altitude_range = float(mobility_conf.get("altitude_range", 200.0))
        duration = float(mobility_conf.get("duration", 60.0))
        time_step = float(mobility_conf.get("time_step", 1.0))
        seed = int(mobility_conf.get("seed", 42))

        random.seed(seed + node.GetId())

        # 初始位置 (随机在3D空间)
        x = random.uniform(-area_size/2, area_size/2)
        y = random.uniform(-area_size/2, area_size/2)
        z = random.uniform(50, 50 + altitude_range)
        pos = [x, y, z]

        # 初始速度向量 (球坐标随机)
        speed = max(random.gauss(speed_mean, speed_std), 5.0)  # 最小5m/s
        theta = random.uniform(0, 2 * math.pi)  # 水平方向
        phi = random.uniform(0, math.pi)  # 垂直方向 (0=up, pi=down)

        vx = speed * math.sin(phi) * math.cos(theta)
        vy = speed * math.sin(phi) * math.sin(theta)
        vz = speed * math.cos(phi)

        # 生成轨迹
        waypoints = [[0.0, list(pos)]]
        t = 0.0

        while t < duration:
            t += time_step

            # Gauss-Markov更新速度
            # v_new = alpha * v_old + (1-alpha) * v_mean + sqrt(1-alpha^2) * N(0, sigma)
            speed_old = math.sqrt(vx*vx + vy*vy + vz*vz)

            # 新速度大小 (Gauss-Markov)
            speed_new = (alpha * speed_old +
                        (1 - alpha) * speed_mean +
                        math.sqrt(1 - alpha*alpha) * random.gauss(0, speed_std))
            speed_new = max(speed_new, 5.0)  # 最小5m/s

            # 新方向 (有记忆性 + 随机扰动)
            # 水平方向更新
            theta_change = random.gauss(0, (1-alpha) * math.pi / 4)
            theta = theta * alpha + theta_change

            # 垂直方向更新 (限制在合理范围)
            phi_change = random.gauss(0, (1-alpha) * math.pi / 8)
            phi = phi * alpha + phi_change
            # 限制垂直角度避免过度爬升/俯冲
            phi = max(math.pi/6, min(5*math.pi/6, phi))

            # 计算新速度向量
            vx = speed_new * math.sin(phi) * math.cos(theta)
            vy = speed_new * math.sin(phi) * math.sin(theta)
            vz = speed_new * math.cos(phi)

            # 更新位置
            pos[0] += vx * time_step
            pos[1] += vy * time_step
            pos[2] += vz * time_step

            # 边界检查与反弹
            if abs(pos[0]) > area_size/2:
                pos[0] = math.copysign(area_size/2 - 10, pos[0])
                vx = -vx
                theta = math.atan2(vy, vx)
            if abs(pos[1]) > area_size/2:
                pos[1] = math.copysign(area_size/2 - 10, pos[1])
                vy = -vy
                theta = math.atan2(vy, vx)
            if pos[2] < 30 or pos[2] > 50 + altitude_range:  # 安全高度
                pos[2] = max(30, min(50 + altitude_range, pos[2]))
                vz = -vz
                phi = math.atan2(math.sqrt(vx*vx + vy*vy), vz)

            waypoints.append([round(t, 2), [round(pos[0], 2), round(pos[1], 2), round(pos[2], 2)]])

        MobilityFactory._install_waypoint(node, waypoints)

    # =========================
    # Gauss-Markov 3D - 真正的运行时版本
    # =========================

    @staticmethod
    def _install_gauss_markov_3d_runtime(node, mobility_conf):
        """
        真正的Gauss-Markov 3D移动模型 - NS3运行时实现
        
        不同于预计算航点，此模型在NS3仿真运行时动态更新速度：
        - 每个timestep (0.1s) 重新计算速度向量
        - 使用Gauss-Markov方程: v_new = α*v_old + (1-α)*v_mean + √(1-α²)*N(0,σ)
        - 支持3D边界反弹
        - 支持高度约束
        
        学术标准参数:
        - alpha: 0.7 (速度相关系数)
        - update_interval: 0.1s (10Hz，顶会标准)
        """
        import random
        import math

        # 读取配置
        alpha = float(mobility_conf.get("alpha", 0.7))
        speed_mean = float(mobility_conf.get("mean_speed_mps", 15.0))
        speed_std = float(mobility_conf.get("speed_std_mps", 5.0))
        mean_altitude = float(mobility_conf.get("mean_altitude_m", 80.0))
        altitude_range = float(mobility_conf.get("altitude_std_m", 20.0)) * 2.5
        
        # 从配置获取仿真区域（密度驱动）
        area_size_x = float(mobility_conf.get("area_size_x", 1000.0))
        area_size_y = float(mobility_conf.get("area_size_y", 1000.0))
        min_altitude = float(mobility_conf.get("min_altitude_m", 30.0))
        max_altitude = float(mobility_conf.get("max_altitude_m", 200.0))
        
        seed = int(mobility_conf.get("seed", 42))
        node_id = node.GetId()
        
        # 独立随机数生成器
        rng = random.Random(seed + node_id)
        
        # 首先安装ConstantPositionMobilityModel作为初始位置
        helper = ns.MobilityHelper()
        helper.SetMobilityModel("ns3::ConstantPositionMobilityModel")
        container = ns.NodeContainer()
        container.Add(node)
        helper.Install(container)
        
        # 获取mobility model
        mobility = node.GetObject[ns.ConstantPositionMobilityModel]()
        
        # 初始位置（如果已配置）
        initial_pos = mobility_conf.get("initial_position")
        if initial_pos:
            mobility.SetPosition(ns.Vector(initial_pos[0], initial_pos[1], initial_pos[2]))
        
        current_pos = mobility.GetPosition()
        position = [current_pos.x, current_pos.y, current_pos.z]
        
        # 初始速度向量（球坐标随机）
        speed = max(rng.gauss(speed_mean, speed_std), 5.0)  # 最小5m/s
        theta = rng.uniform(0, 2 * math.pi)  # 水平方向
        phi = rng.uniform(math.pi/3, 2*math.pi/3)  # 垂直方向（限制爬升角）
        
        velocity = [
            speed * math.sin(phi) * math.cos(theta),
            speed * math.sin(phi) * math.sin(theta),
            speed * math.cos(phi)
        ]
        
        # 定义更新函数
        def update_position():
            nonlocal position, velocity
            
            # 1. 计算当前速度大小
            speed_old = math.sqrt(velocity[0]**2 + velocity[1]**2 + velocity[2]**2)
            
            # 2. Gauss-Markov速度更新
            # v_new = α*v_old + (1-α)*v_mean + √(1-α²)*N(0,σ)
            speed_new = (
                alpha * speed_old +
                (1 - alpha) * speed_mean +
                math.sqrt(1 - alpha**2) * rng.gauss(0, speed_std)
            )
            speed_new = max(speed_new, 5.0)  # 最小速度限制
            
            # 3. 方向更新（有记忆性）
            theta = math.atan2(velocity[1], velocity[0])
            speed_xy = math.sqrt(velocity[0]**2 + velocity[1]**2)
            phi = math.atan2(speed_xy, velocity[2])
            
            # 应用随机扰动
            theta_change = rng.gauss(0, (1 - alpha) * math.pi / 4)
            phi_change = rng.gauss(0, (1 - alpha) * math.pi / 8)
            
            theta = alpha * theta + theta_change
            phi = alpha * phi + phi_change
            
            # 限制垂直角度（避免过度俯冲/爬升）
            phi = max(math.pi/6, min(5*math.pi/6, phi))
            
            # 4. 计算新速度向量
            velocity = [
                speed_new * math.sin(phi) * math.cos(theta),
                speed_new * math.sin(phi) * math.sin(theta),
                speed_new * math.cos(phi)
            ]
            
            # 5. 更新位置
            interval_s = 0.1  # 10Hz更新
            position[0] += velocity[0] * interval_s
            position[1] += velocity[1] * interval_s
            position[2] += velocity[2] * interval_s
            
            # 6. 边界检查与反弹
            if abs(position[0]) > area_size_x / 2:
                position[0] = math.copysign(area_size_x / 2 - 1, position[0])
                velocity[0] = -velocity[0]  # X方向反弹
                
            if abs(position[1]) > area_size_y / 2:
                position[1] = math.copysign(area_size_y / 2 - 1, position[1])
                velocity[1] = -velocity[1]  # Y方向反弹
                
            if position[2] < min_altitude:
                position[2] = min_altitude + 1
                velocity[2] = abs(velocity[2])  # 向上反弹
            elif position[2] > max_altitude:
                position[2] = max_altitude - 1
                velocity[2] = -abs(velocity[2])  # 向下反弹
            
            # 7. 应用新位置到NS3
            new_pos = ns.Vector(position[0], position[1], position[2])
            mobility.SetPosition(new_pos)
            
            # 8. 安排下一次更新
            ns.Simulator.Schedule(ns.Seconds(0.1), update_position)
        
        # 启动更新循环
        ns.Simulator.Schedule(ns.Seconds(0.0), update_position)
        
        # 存储引用和状态（防止垃圾回收）
        if not hasattr(node, '_gm3d_state'):
            node._gm3d_state = []
        node._gm3d_state.append({
            'position': position,
            'velocity': velocity,
            'rng': rng,
            'alpha': alpha,
        })
