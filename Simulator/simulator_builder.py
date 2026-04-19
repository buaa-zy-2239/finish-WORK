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

        self.blockchain = Web3BlockchainAdapter()

        self.stats = {
            "start_time": None,
            "end_time": None,
            "total_uavs": 0,
            "total_zsps": 0,
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
            self._pre_reg()

            duration = self.config.get("simulation", {}).get("duration", 30)
            ns.Simulator.Stop(ns.Seconds(duration))

            print(f"[BUILDER] Running simulation for {duration} seconds...")
            ns.Simulator.Run()
            ns.Simulator.Destroy()

            self.stats["end_time"] = datetime.now().isoformat()
            self.stats["total_uavs"] = len(self.uavs)
            self.stats["total_zsps"] = len(self.zsps)

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
        total = max_id + 1
        self.nodes = ns.NodeContainer()
        self.nodes.Create(total)
        print(f"[BUILDER] Created {total} nodes")

    def _setup_network(self):
        stack = ns.InternetStackHelper()
        stack.Install(self.nodes)

        address = ns.Ipv4AddressHelper()
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
        # 使用YansWifiChannel支持PropagationLossModel
        wifi_channel = ns.YansWifiChannelHelper.Default()

        # 配置路径损耗模型: Friis + Nakagami-m (IEEE TWC标准)
        # 1. Friis自由空间路径损耗 (近场)
        # 2. LogDistance (远场)
        # 3. Nakagami-m衰落 (多径效应)

        loss_model = channel_config.get("loss_model", "friis_log_distance")

        if loss_model == "friis_log_distance":
            # Friis for short distance (< breakpoint), then LogDistance
            wifi_channel.AddPropagationLoss(
                "ns3::FriisPropagationLossModel"
            )
        elif loss_model == "nakagami":
            # Nakagami-m fading (typical for UAV A2G channel)
            # m=1 (Rayleigh), m=2-4 (Rician-like)
            m0 = float(channel_config.get("nakagami_m0", 1.5))
            m1 = float(channel_config.get("nakagami_m1", 0.75))
            m2 = float(channel_config.get("nakagami_m2", 0.5))

            wifi_channel.AddPropagationLoss(
                "ns3::NakagamiPropagationLossModel",
                "Distance1", ns.DoubleValue(50.0),  # m0 for d < 50m
                "Distance2", ns.DoubleValue(150.0),  # m1 for 50m < d < 150m
                "m0", ns.DoubleValue(m0),
                "m1", ns.DoubleValue(m1),
                "m2", ns.DoubleValue(m2),
            )
        elif loss_model == "range":
            # 简单范围限制模型 (用于快速测试)
            max_range = float(channel_config.get("max_range", 500.0))
            wifi_channel.AddPropagationLoss(
                "ns3::RangePropagationLossModel",
                "MaxRange", ns.DoubleValue(max_range)
            )

        # 延迟模型
        wifi_channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel")

        # WiFi PHY配置 (802.11ah - suitable for long-range IoT/UAV)
        wifi_phy = ns.YansWifiPhyHelper()
        wifi_phy.SetChannel(wifi_channel.Create())

        # 使用802.11ah标准 (Sub-1GHz, long range, lower rate)
        # 适合UAV通信场景
        wifi_std = ns.WifiStandard.WIFI_STANDARD_80211ah
        wifi_phy.Set("Standard", ns.EnumValue(wifi_std))

        # 数据率配置
        datarate = channel_config.get("datarate", "6Mbps")
        wifi_phy.Set("DataRate", ns.StringValue(datarate))

        # MAC配置 (Ad-hoc模式适合UAV自组织网络)
        wifi_mac = ns.WifiMacHelper()
        wifi_mac.SetType("ns3::AdhocWifiMac")

        # 安装WiFi设备
        wifi = ns.WifiHelper()
        wifi.SetStandard(wifi_std)
        devices = wifi.Install(wifi_phy, wifi_mac, self.nodes)

        self.interfaces = address.Assign(devices)

    def _setup_zsp(self):
        for zsp_conf in self.config.get("zsps", []):
            node = self.nodes.Get(zsp_conf["id"])
            zid = int(zsp_conf["id"])

            zsp = self.protocol_spec.zsp_class(
                node,
                zid,
                blockchain=self.blockchain,
                enable_blockchain=True,
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

    def _pre_reg(self):
        for uav in self.uavs:
            reg = uav.get_registration_record()
            for zsp in self.zsps:
                zsp.RegisterUAV(reg["pid"], copy.deepcopy(reg))
        print(f"[BUILDER] Pre-registered {len(self.uavs)} UAVs ({self.protocol})")


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
