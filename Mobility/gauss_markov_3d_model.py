"""
真正的Gauss-Markov 3D移动模型 - NS3运行时实现

实现为Python绑定到NS3 MobilityModel，在仿真运行时动态更新速度
符合IEEE TWC/INFOCOM标准
"""

from ns import ns
import random
import math


class GaussMarkov3DModel:
    """
    真正的Gauss-Markov 3D移动模型 (NS3运行时版本)
    
    不同于预计算航点，此模型在NS3仿真运行时动态更新速度：
    - 每个timestep重新计算速度向量
    - 使用Gauss-Markov方程: v_new = α*v_old + (1-α)*v_mean + √(1-α²)*N(0,σ)
    - 支持3D边界反弹
    - 支持高度约束
    
    学术标准参数:
    - alpha: 0.7 (速度相关系数)
    - update_interval: 0.1s (10Hz，顶会标准)
    """
    
    def __init__(self):
        self.alpha = 0.7
        self.speed_mean = 15.0  # m/s
        self.speed_std = 5.0
        self.mean_altitude = 80.0  # m
        self.altitude_range = 50.0  # ±50m
        self.area_size_x = 1000.0
        self.area_size_y = 1000.0
        self.min_altitude = 30.0
        self.max_altitude = 200.0
        
        # 当前状态
        self.velocity = [0.0, 0.0, 0.0]  # m/s
        self.position = [0.0, 0.0, 80.0]
        
        # 随机数生成器（独立种子）
        self.rng = random.Random()
        
        # NS3事件句柄
        self.update_event = None
        self.update_interval = ns.Seconds(0.1)  # 10Hz更新
        
    def initialize(self, node, mobility_conf):
        """
        初始化模型参数和状态
        
        Args:
            node: NS3节点对象
            mobility_conf: 配置字典
        """
        # 读取配置
        self.alpha = float(mobility_conf.get("alpha", 0.7))
        self.speed_mean = float(mobility_conf.get("mean_speed_mps", 15.0))
        self.speed_std = float(mobility_conf.get("speed_std_mps", 5.0))
        self.mean_altitude = float(mobility_conf.get("mean_altitude_m", 80.0))
        self.altitude_range = float(mobility_conf.get("altitude_std_m", 20.0)) * 2.5
        self.area_size_x = float(mobility_conf.get("area_size_x", 1000.0))
        self.area_size_y = float(mobility_conf.get("area_size_y", 1000.0))
        
        seed = int(mobility_conf.get("seed", 42))
        node_id = node.GetId()
        self.rng.seed(seed + node_id)
        
        # 获取NS3 mobility model引用
        self.mobility = node.GetObject[ns.MobilityModel]()
        if not self.mobility:
            raise RuntimeError("Node must have MobilityModel installed")
        
        # 初始位置
        current_pos = self.mobility.GetPosition()
        self.position = [current_pos.x, current_pos.y, current_pos.z]
        
        # 初始速度（随机方向）
        speed = max(self.rng.gauss(self.speed_mean, self.speed_std), 5.0)
        theta = self.rng.uniform(0, 2 * math.pi)  # 水平方向
        phi = self.rng.uniform(math.pi/3, 2*math.pi/3)  # 垂直方向（限制爬升角）
        
        self.velocity = [
            speed * math.sin(phi) * math.cos(theta),
            speed * math.sin(phi) * math.sin(theta),
            speed * math.cos(phi)
        ]
        
        # 启动更新循环
        self._schedule_next_update()
        
    def _schedule_next_update(self):
        """安排下一次位置更新"""
        self.update_event = ns.Simulator.Schedule(
            self.update_interval,
            self._update_position,
        )
        
    def _update_position(self):
        """
        核心GM3D更新函数
        
        在每个timestep执行:
        1. 使用Gauss-Markov方程计算新速度
        2. 更新位置
        3. 边界检查与反弹
        4. 安排下一次更新
        """
        # 1. 计算当前速度大小
        speed_old = math.sqrt(
            self.velocity[0]**2 + 
            self.velocity[1]**2 + 
            self.velocity[2]**2
        )
        
        # 2. Gauss-Markov速度更新
        # v_new = α*v_old + (1-α)*v_mean + √(1-α²)*N(0,σ)
        speed_new = (
            self.alpha * speed_old +
            (1 - self.alpha) * self.speed_mean +
            math.sqrt(1 - self.alpha**2) * self.rng.gauss(0, self.speed_std)
        )
        speed_new = max(speed_new, 5.0)  # 最小速度限制
        
        # 3. 方向更新（有记忆性）
        # 计算当前方向角
        theta = math.atan2(self.velocity[1], self.velocity[0])
        speed_xy = math.sqrt(self.velocity[0]**2 + self.velocity[1]**2)
        phi = math.atan2(speed_xy, self.velocity[2])
        
        # 应用随机扰动
        theta_change = self.rng.gauss(0, (1 - self.alpha) * math.pi / 4)
        phi_change = self.rng.gauss(0, (1 - self.alpha) * math.pi / 8)
        
        theta = self.alpha * theta + theta_change
        phi = self.alpha * phi + phi_change
        
        # 限制垂直角度
        phi = max(math.pi/6, min(5*math.pi/6, phi))
        
        # 4. 计算新速度向量
        self.velocity = [
            speed_new * math.sin(phi) * math.cos(theta),
            speed_new * math.sin(phi) * math.sin(theta),
            speed_new * math.cos(phi)
        ]
        
        # 5. 更新位置
        interval_s = self.update_interval.GetSeconds()
        self.position[0] += self.velocity[0] * interval_s
        self.position[1] += self.velocity[1] * interval_s
        self.position[2] += self.velocity[2] * interval_s
        
        # 6. 边界检查与反弹
        if abs(self.position[0]) > self.area_size_x / 2:
            self.position[0] = math.copysign(
                self.area_size_x / 2 - 1, 
                self.position[0]
            )
            self.velocity[0] = -self.velocity[0]
            
        if abs(self.position[1]) > self.area_size_y / 2:
            self.position[1] = math.copysign(
                self.area_size_y / 2 - 1,
                self.position[1]
            )
            self.velocity[1] = -self.velocity[1]
            
        if self.position[2] < self.min_altitude:
            self.position[2] = self.min_altitude + 1
            self.velocity[2] = abs(self.velocity[2])  # 向上反弹
        elif self.position[2] > self.max_altitude:
            self.position[2] = self.max_altitude - 1
            self.velocity[2] = -abs(self.velocity[2])  # 向下反弹
        
        # 7. 应用新位置到NS3
        new_ns3_pos = ns.Vector(
            self.position[0],
            self.position[1],
            self.position[2]
        )
        self.mobility.SetPosition(new_ns3_pos)
        
        # 8. 安排下一次更新
        self._schedule_next_update()
        
    def get_velocity(self):
        """获取当前速度向量"""
        return tuple(self.velocity)
        
    def get_speed(self):
        """获取当前速度大小"""
        return math.sqrt(sum(v**2 for v in self.velocity))


class MobilityFactory:
    """增强的MobilityFactory，支持真正的GM3D"""
    
    @staticmethod
    def install_gauss_markov_3d_runtime(node, mobility_conf):
        """
        安装真正的运行时Gauss-Markov 3D模型
        
        与预计算版本不同，此版本在NS3仿真运行时动态更新位置
        """
        # 首先安装ConstantVelocityMobilityModel作为基础
        helper = ns.MobilityHelper()
        helper.SetMobilityModel("ns3::ConstantVelocityMobilityModel")
        
        container = ns.NodeContainer()
        container.Add(node)
        helper.Install(container)
        
        # 然后附加GM3D逻辑
        gm3d_model = GaussMarkov3DModel()
        gm3d_model.initialize(node, mobility_conf)
        
        # 存储引用（防止垃圾回收）
        if not hasattr(node, '_gm3d_models'):
            node._gm3d_models = []
        node._gm3d_models.append(gm3d_model)
        
        return gm3d_model
