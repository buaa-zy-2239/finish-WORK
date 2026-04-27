# Simulator/simulator_builder_enhanced.py
"""
增强的仿真构建器 - PMAP / PMAP_ACK（D2Z 下行 ACK 会话冗余）、动态配置与日志。

入口位于仓库根目录，便于 `ns3 run .../UAV/simulator_builder.py`；`_ROOT` 指向本仓库 UAV 根。
"""

import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime

_ROOT = Path(__file__).resolve().parent
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

        # 初始化用户数量
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

        address = ns.Ipv4AddressHelper()
        address.SetBase(ns.Ipv4Address("10.1.1.0"), ns.Ipv4Mask("255.255.255.0"))

        channel = ns.CsmaHelper()
        channel_config = self.config.get("channel", {})
        channel.SetChannelAttribute("DataRate", ns.StringValue(channel_config.get("datarate", "100Mbps")))
        channel.SetChannelAttribute("Delay", ns.TimeValue(ns.NanoSeconds(6560)))

        devices = channel.Install(self.nodes)
        self.interfaces = address.Assign(devices)
        print("[BUILDER] Network stack installed")

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
            # 限制用户数量，避免内存使用过度
            max_users = 5
            if self.user_count > max_users:
                print(f"[BUILDER] User count {self.user_count} exceeds maximum {max_users}, setting to {max_users}")
                self.user_count = max_users
            
            # 为三方认证协议创建用户
            try:
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
                    
                    # 模拟连接到ZSP
                    user.on_connected_to_zsp(1)  # 假设连接到ZSP 1
                    
                    print(f"[BUILDER] User-{i} created with node ID {user_node_id} ({self.protocol})")
            except Exception as e:
                print(f"[BUILDER] Error creating users: {e}")
                import traceback
                traceback.print_exc()

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
