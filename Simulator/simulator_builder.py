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
from Mobility.mobility import MobilityFactory
from Entity.UAV.PMAPUAV import PMAP_UAV
from Entity.ZSP.PMAPZSP import PMAP_ZSP
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

        proto = (self.config.get("protocol") or "PMAP").strip().upper()
        if proto not in ("PMAP", "PMAP_ACK"):
            proto = "PMAP"
        self.protocol = proto
        self.d2z_ack_mode = proto == "PMAP_ACK"

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

            zsp = PMAP_ZSP(
                node,
                zid,
                blockchain=self.blockchain,
                enable_blockchain=True,
                attack_model=self.attack_model,
                d2z_ack_mode=self.d2z_ack_mode,
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
            MobilityFactory.install(node, uav_conf.get("mobility", {}))

            uav = PMAP_UAV(
                node,
                uid,
                attack_model=self.attack_model,
                d2z_ack_mode=self.d2z_ack_mode,
            )

            self.uavs.append(uav)
            node.AddApplication(uav)
            uav.SetStartTime(ns.Seconds(0))
            print(f"[BUILDER] UAV-{uid} created ({self.protocol})")

    def _pre_reg(self):
        for uav in self.uavs:
            reg = {"uav_id": uav.id, "crp": uav.crp, "pid": uav.pid}
            for zsp in self.zsps:
                zsp.RegisterUAV(uav.pid, copy.deepcopy(reg))
        print(f"[BUILDER] Pre-registered {len(self.uavs)} UAVs (PMAP)")


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
