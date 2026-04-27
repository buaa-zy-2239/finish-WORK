# Simulator/simulator_builder_enhanced.py
"""
增强的仿真构建器 - PMAP / PMAP_ACK（D2Z 下行 ACK 会话冗余）、动态配置与日志。
"""

import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from ns import ns

from Common.logging_framework import get_log_manager, reset_log_manager
from Common.attack_model import merge_attack_model
from Common.desync_attack_template import apply_desync_template
from Common.protocol_registry import get_protocol_spec
from Common.scenario_inputs import load_waypoints_from_json_file, resolve_config_relative_path
from Mobility.mobility import MobilityFactory
from BlockChain.Blockchain import Web3BlockchainAdapter
import copy

address = ns.Ipv4AddressHelper()
class SimulationBuilderEnhanced:
    """增强的仿真构建器（PMAP 或 PMAP_ACK）。"""

    def __init__(self, config_path=None, config_dict=None):
        if config_path:
            self.config = self._load_json(config_path)
        elif config_dict:
            self.config = config_dict
        else:
            raise ValueError("Must provide config_path or config_dict")
        self._config_dir = str(Path(config_path).resolve().parent) if config_path else None

        self.protocol_spec = get_protocol_spec(self.config.get("protocol"))
        self.protocol = self.protocol_spec.name
        self.d2z_ack_mode = bool(self.protocol_spec.builder_options.get("d2z_ack_mode", False))

        self.attack_model = apply_desync_template(merge_attack_model(self.config))
        self.interfaces = None

        self.nodes = None
        self.uavs = []
        self.zsps = []
        self.users = []

        # 初始化区块链（根据配置决定是否开启）
        self.enable_blockchain = self.config.get("enable_blockchain", False)
        self.blockchain = None
        if self.enable_blockchain:
            try:
                self.blockchain = Web3BlockchainAdapter()
                print("[Blockchain] Initialized")
            except RuntimeError as e:
                print(f"[Blockchain] Failed to initialize: {e}")
                self.enable_blockchain = False
                self.blockchain = None
        else:
            print("[Blockchain] Disabled")
        
        self.user_count = self.config.get("user_count", 0)

        self.stats = {
            "start_time": None,
            "end_time": None,
            "total_uavs": 0,
            "total_zsps": 0,
            "total_users": 0,
            "total_messages": 0,
            "successful_authentications": 0,
            "failed_authentications": 0,
        }

        print(f"[BUILDER] SimulationBuilderEnhanced initialized (protocol={self.protocol})")

    def _load_json(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)
            print(f"[BUILDER] Loaded config from {path}")
            return config
        except Exception as e:
            print(f"[BUILDER] JSON load error: {e}")
            raise

    def run(self):
        try:
            print("[BUILDER] Starting simulation build and execution...")
            self.stats["start_time"] = datetime.now().isoformat()

            log_dir = os.environ.get("SIM_LOG_DIR", "/home/zhang/UAV/logs")
            os.makedirs(log_dir, exist_ok=True)
            sim_id_raw = os.environ.get("SIM_ID", "").strip()
            try:
                sim_id = int(sim_id_raw) if sim_id_raw else int(time.time()) % (10**9)
            except ValueError:
                sim_id = abs(hash(sim_id_raw)) % (10**9)
            reset_log_manager()
            get_log_manager(log_dir, sim_id)
            print(f"[BUILDER] Log output: dir={log_dir} sim_id={sim_id} protocol={self.protocol}")

            self._create_nodes()
            self._setup_network()
            self._setup_zsp()
            self._setup_uav()
            self._setup_user()
            self._pre_reg()

            duration = self.config.get("simulation", {}).get("duration", 30)
            ns.Simulator.Stop(ns.Seconds(duration))

            print(f"[BUILDER] Running simulation for {duration} seconds...")
            ns.Simulator.Run()
            ns.Simulator.Destroy()

            self.stats["end_time"] = datetime.now().isoformat()
            self.stats["total_uavs"] = len(self.uavs)
            self.stats["total_zsps"] = len(self.zsps)
            self.stats["total_users"] = len(self.users)

            print("[BUILDER] Simulation completed successfully")

            return {
                "status": "completed",
                "statistics": self.stats,
                "uav_count": len(self.uavs),
                "zsp_count": len(self.zsps),
                "protocol": self.protocol,
            }

        except Exception as e:
            print(f"[BUILDER] Simulation failed: {e}")
            import traceback

            traceback.print_exc()

            self.stats["end_time"] = datetime.now().isoformat()

            return {
                "status": "failed",
                "error": str(e),
                "statistics": self.stats,
                "protocol": self.protocol,
            }

    def _create_nodes(self):
        max_id = 0
        for u in self.config.get("uavs", []):
            max_id = max(max_id, u.get("id", 0))
        for z in self.config.get("zsps", []):
            max_id = max(max_id, z.get("id", 0))
        
        # 为用户分配节点ID，从max_id+1开始
        if self.user_count > 0:
            total = max_id + 1 + self.user_count
        else:
            total = max_id + 1
            
        self.nodes = ns.NodeContainer()
        self.nodes.Create(total)
        print(f"[BUILDER] Created {total} nodes (UAVs: {len(self.config.get('uavs', []))}, ZSPs: {len(self.config.get('zsps', []))}, Users: {self.user_count})")

    def _setup_network(self):
        stack = ns.InternetStackHelper()
        stack.Install(self.nodes)

        
        address.SetBase(ns.Ipv4Address("10.1.1.0"), ns.Ipv4Mask("255.255.255.0"))

        channel_config = self.config.get("channel", {})
        channel_type = channel_config.get("type", "CSMA")

        if channel_type == "WiFi":
            # 使用WiFi信道模拟无线环境 (IEEE 802.11ah for IoT/UAV)
            self._setup_wifi_network(channel_config)
        else:
            # 默认CSMA (向后兼容)
            channel = ns.CsmaHelper()
            channel.SetChannelAttribute("DataRate", ns.StringValue(channel_config.get("datarate", "100Mbps")))
            channel.SetChannelAttribute("Delay", ns.TimeValue(ns.NanoSeconds(6560)))
            devices = channel.Install(self.nodes)
            self.interfaces = address.Assign(devices)

        print(f"[BUILDER] Network stack installed ({channel_type})")

    def _setup_wifi_network(self, channel_config):
        """设置WiFi网络，支持路径损耗和衰落模型 (IEEE 802.11ah)"""
        loss_model = channel_config.get("loss_model", "friis_log_distance")
        
        if loss_model == "3gpp_uav":
            # 3GPP UAV信道模型：手动创建channel，确保PropagationLossModel正确应用
            wifi_channel = ns.YansWifiChannelHelper()
            wifi_channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel")
            self._setup_3gpp_uav_channel(wifi_channel, channel_config)
        else:
            # 其他模型：使用Default配置
            wifi_channel = ns.YansWifiChannelHelper.Default()
            
            if loss_model == "friis_log_distance":
                wifi_channel.AddPropagationLoss("ns3::FriisPropagationLossModel")
            elif loss_model == "nakagami":
                m0 = float(channel_config.get("nakagami_m0", 1.5))
                m1 = float(channel_config.get("nakagami_m1", 0.75))
                m2 = float(channel_config.get("nakagami_m2", 0.5))
                wifi_channel.AddPropagationLoss(
                    "ns3::NakagamiPropagationLossModel",
                    "Distance1", ns.DoubleValue(50.0),
                    "Distance2", ns.DoubleValue(150.0),
                    "m0", ns.DoubleValue(m0),
                    "m1", ns.DoubleValue(m1),
                    "m2", ns.DoubleValue(m2),
                )
            elif loss_model == "range":
                max_range = float(channel_config.get("max_range", 500.0))
                wifi_channel.AddPropagationLoss(
                    "ns3::RangePropagationLossModel",
                    "MaxRange", ns.DoubleValue(max_range)
                )

        # WiFi PHY配置
        wifi_phy = ns.YansWifiPhyHelper()
        wifi_phy.SetChannel(wifi_channel.Create())

        # MAC配置 (Ad-hoc模式)
        wifi_mac = ns.WifiMacHelper()
        wifi_mac.SetType("ns3::AdhocWifiMac")

        # WiFi Helper配置
        wifi = ns.WifiHelper()
        wifi.SetStandard(ns.WifiStandard.WIFI_STANDARD_80211g)
        
        # 数据率配置
        datarate = channel_config.get("datarate", "DsssRate1Mbps")
        wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode", ns.StringValue(datarate),
                                     "ControlMode", ns.StringValue(datarate))
        
        devices = wifi.Install(wifi_phy, wifi_mac, self.nodes)
        self.interfaces = address.Assign(devices)

    def _setup_3gpp_uav_channel(self, wifi_channel, channel_config):
        """设置3GPP UAV信道模型 (基于3GPP TR 36.777)
        
        该模型考虑了：
        - 无人机高度依赖的路径损耗
        - LoS (Line-of-Sight) 概率
        - A2G (Air-to-Ground) 信道特性
        - 阴影衰落
        - 多径衰落
        
        适用场景：无人机高度 > 40m 的城区环境
        
        使用ns-3现有模型组合实现：
        - LogDistancePropagationLossModel (路径损耗)
        - NakagamiPropagationLossModel (多径衰落)
        - RandomPropagationLossModel (阴影衰落)
        """
        import math
        
        # 获取配置参数
        uav_height = float(channel_config.get("uav_height_m", 80.0))  # 默认无人机高度80m
        env_type = channel_config.get("environment", "urban")  # urban/suburban/rural
        carrier_freq = float(channel_config.get("carrier_freq_ghz", 2.4))  # 载波频率GHz
        
        # 3GPP TR 36.777 A2G路径损耗模型参数
        # 环境参数配置
        env_params = {
            "urban": {
                "a": 0.0,  # 常数项
                "b": 1.0,  # 距离指数
                "c": 0.0,  # 高度指数
                "sigma_shadow": 8.0,  # 阴影衰落标准差 (dB)
                "los_prob_alpha": 0.1,  # LoS概率参数
                "los_prob_beta": 0.5,   # LoS概率参数
            },
            "suburban": {
                "a": 0.0,
                "b": 0.8,
                "c": 0.0,
                "sigma_shadow": 6.0,
                "los_prob_alpha": 0.05,
                "los_prob_beta": 0.4,
            },
            "rural": {
                "a": 0.0,
                "b": 0.6,
                "c": 0.0,
                "sigma_shadow": 4.0,
                "los_prob_alpha": 0.02,
                "los_prob_beta": 0.3,
            }
        }
        
        params = env_params.get(env_type, env_params["urban"])
        
        # 参考损耗 d0 (自由空间损耗)
        d0 = 1.0  # 1m参考距离
        c = 3e8  # 光速 m/s
        PLd0 = 20 * math.log10(4 * math.pi * d0 * carrier_freq * 1e9 / c)
        
        # 配置A2G路径损耗模型
        # 使用LogDistance模型模拟A2G路径损耗
        # 路径损耗指数根据环境类型调整
        path_loss_exp = 2.7  # 与BaseUAV.py中的n值一致
        
        # 配置LogDistance模型
        wifi_channel.AddPropagationLoss(
            "ns3::LogDistancePropagationLossModel",
            "Exponent", ns.DoubleValue(path_loss_exp),  # 路径损耗指数
            "ReferenceLoss", ns.DoubleValue(PLd0),  # 参考损耗 d0
            "ReferenceDistance", ns.DoubleValue(1.0),  # 参考距离 1m
        )
        
        # 添加阴影衰落 (Shadowing)
        sigma_shadow = params["sigma_shadow"]
        wifi_channel.AddPropagationLoss(
            "ns3::RandomPropagationLossModel",
            "Variable", ns.StringValue(f"ns3::NormalRandomVariable[Mean=0|Variance={sigma_shadow**2}]")
        )
        
        # 添加多径衰落 (Nakagami-m)
        # 根据环境类型调整Nakagami参数
        if env_type == "urban":
            m0 = 1.5  # 近场 (LoS)
            m1 = 1.0  # 中场 (NLoS)
            m2 = 0.5  # 远场 (NLoS)
        elif env_type == "suburban":
            m0 = 2.0
            m1 = 1.5
            m2 = 1.0
        else:  # rural
            m0 = 2.5
            m1 = 2.0
            m2 = 1.5
        
        wifi_channel.AddPropagationLoss(
            "ns3::NakagamiPropagationLossModel",
            "Distance1", ns.DoubleValue(50.0),  # m0 for d < 50m
            "Distance2", ns.DoubleValue(150.0),  # m1 for 50m < d < 150m
            "m0", ns.DoubleValue(m0),
            "m1", ns.DoubleValue(m1),
            "m2", ns.DoubleValue(m2),
        )

    def _setup_zsp(self):
        for zsp_conf in self.config.get("zsps", []):
            node = self.nodes.Get(zsp_conf["id"])
            zid = int(zsp_conf["id"])

            zsp = self.protocol_spec.zsp_class(
                node,
                zid,
                blockchain=self.blockchain,
                enable_blockchain=self.enable_blockchain,
                attack_model=self.attack_model,
                d2z_ack_mode=self.d2z_ack_mode,
                compute_profile=zsp_conf.get("compute_profile"),
            )

            MobilityFactory.install_constant(node, zsp_conf.get("position", [0, 0, 100]))
            self.zsps.append(zsp)
            node.AddApplication(zsp)
            zsp.SetStartTime(ns.Seconds(0))
            print(f"[BUILDER] ZSP-{zid} created ({self.protocol})")

    def _setup_uav(self):
        for uav_conf in self.config.get("uavs", []):
            node = self.nodes.Get(uav_conf["id"])
            uid = int(uav_conf["id"])
            mobility_conf = dict(uav_conf.get("mobility", {}))
            if mobility_conf.get("type") == "trace" and mobility_conf.get("trace_file"):
                trace_path = resolve_config_relative_path(self._config_dir, mobility_conf.get("trace_file"))
                mobility_conf["waypoints"] = load_waypoints_from_json_file(trace_path)
            MobilityFactory.install(node, mobility_conf)

            uav = self.protocol_spec.uav_class(
                node,
                uid,
                attack_model=self.attack_model,
                d2z_ack_mode=self.d2z_ack_mode,
                auth_trigger_config=uav_conf.get("auth_trigger"),
                link_state_config=uav_conf.get("link_state"),
            )

            self.uavs.append(uav)
            node.AddApplication(uav)
            uav.SetStartTime(ns.Seconds(0))
            print(f"[BUILDER] UAV-{uid} created ({self.protocol})")

    def _setup_user(self):
        if self.user_count > 0 and self.protocol == 'RLBA_3WAY':
            # 为三方认证协议创建用户
            from Entity.User.RLBAUser import RLBAUser
            
            # 计算用户节点ID的起始值
            max_id = 0
            for u in self.config.get("uavs", []):
                max_id = max(max_id, u.get("id", 0))
            for z in self.config.get("zsps", []):
                max_id = max(max_id, z.get("id", 0))
            user_node_start_id = max_id + 1
            
            for i in range(self.user_count):
                user_id = f"user_{i}"
                gss_id = self.zsps[0].id if self.zsps else ""
                # 生成用户密钥
                import hashlib
                secret = hashlib.sha256(f"RLBA_SECRET:{user_id}".encode()).hexdigest()
                
                # 分配节点给用户
                user_node_id = user_node_start_id + i
                node = self.nodes.Get(user_node_id)
                
                # 创建用户实例
                user = RLBAUser(node, user_id, gss_id, secret)
                self.users.append(user)
                
                # 为用户设置位置（固定位置）
                position = [100 + i * 50, 100, 1.0]  # 地面用户，高度1米
                MobilityFactory.install_constant(node, position)
                
                # 安装用户应用
                node.AddApplication(user)
                user.SetStartTime(ns.Seconds(0))
                
                # 设置logger
                user.logger = self.logger
                
                # 模拟连接到ZSP
                user.on_connected_to_zsp(1)  # 假设连接到ZSP 1
                
                print(f"[BUILDER] User-{i} created with node ID {user_node_id} ({self.protocol})")

    def _pre_reg(self):
        for uav in self.uavs:
            reg = uav.get_registration_record()
            for zsp in self.zsps:
                zsp.RegisterUAV(reg["pid"], copy.deepcopy(reg))
        print(f"[BUILDER] Pre-registered {len(self.uavs)} UAVs ({self.protocol})")
        
        # 部署智能合约（如果启用了区块链）
        if self.enable_blockchain and self.blockchain:
            if hasattr(self.blockchain, 'deploy_contract'):
                self.blockchain.deploy_contract()
                print("[Blockchain] Contract deployed and ready")
            else:
                print("[Blockchain] deploy_contract method not available")


if __name__ == "__main__":
    config_file = os.getenv("CONFIG_FILE", str(_ROOT / "config.json"))
    if not os.path.exists(config_file):
        print(f"[ERROR] Config file not found: {config_file}")
        sys.exit(1)

    builder = SimulationBuilderEnhanced(config_path=config_file)
    result = builder.run()

    print("\n" + "=" * 60)
    print("SIMULATION RESULT SUMMARY")
    print("=" * 60)
    print(json.dumps(result, indent=2, default=str))
    print("=" * 60)

    sys.exit(0 if result["status"] == "completed" else 1)
