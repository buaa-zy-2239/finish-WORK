"""
增强的仿真构建器 - PMAP / PMAP_ACK（D2Z 下行 ACK 会话冗余）、动态配置与日志。
"""

import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime
import copy

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
from Simulator.session_tracker import SessionTracker
from Simulator.network_config import NetworkConfigurator


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

        self.session_tracker = None

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

            self.session_tracker = SessionTracker(sim_id, log_dir)
            print(f"[BUILDER] SessionTracker initialized (sim_id={sim_id})")

            self._create_nodes()
            self._setup_mobility()
            self._install_internet_stack()
            self._setup_network()
            self._setup_zsp()
            self._setup_uav()
            self._setup_user()
            self._pre_reg()

            duration = self.config.get("simulation", {}).get("duration", 30)
            if "duration" in self.config:
                duration = self.config["duration"]
            ns.Simulator.Stop(ns.Seconds(duration))

            print(f"[BUILDER] Running simulation for {duration} seconds...")
            ns.Simulator.Run()
            ns.Simulator.Destroy()

            self.stats["end_time"] = datetime.now().isoformat()
            self.stats["total_uavs"] = len(self.uavs)
            self.stats["total_zsps"] = len(self.zsps)
            self.stats["total_users"] = len(self.users)

            if self.session_tracker:
                results = self.session_tracker.export_results()
                output_path = self.session_tracker.save_results()
                print(f"[BUILDER] SessionTracker results saved to {output_path}")
                self.stats["session_tracker_metrics"] = results.get("metrics", {})
                self.stats["total_sessions"] = len(results.get("sessions", []))
                self.stats["total_events"] = results.get("event_count", 0)

            print("[BUILDER] Simulation completed successfully")

            return {
                "status": "completed",
                "statistics": self.stats,
                "uav_count": len(self.uavs),
                "zsp_count": len(self.zsps),
                "protocol": self.protocol,
                "session_tracker_results": self.session_tracker.export_results() if self.session_tracker else None,
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
        self.nodes = NetworkConfigurator.create_nodes(self.config, self.user_count)
        print(f"[BUILDER] Created {self.nodes.GetN()} nodes")

    def _setup_mobility(self):
        uav_count = len(self.config.get("uavs", []))
        
        for idx, uav_conf in enumerate(self.config.get("uavs", [])):
            node = self.nodes.Get(idx)
            mobility_conf = dict(uav_conf.get("mobility", {}))
            if mobility_conf.get("type") == "trace" and mobility_conf.get("trace_file"):
                trace_path = resolve_config_relative_path(self._config_dir, mobility_conf.get("trace_file"))
                mobility_conf["waypoints"] = load_waypoints_from_json_file(trace_path)
            MobilityFactory.install(node, mobility_conf)

        for idx, zsp_conf in enumerate(self.config.get("zsps", [])):
            node = self.nodes.Get(uav_count + idx)
            MobilityFactory.install_constant(node, zsp_conf.get("position", [0, 0, 100]))

        print(f"[BUILDER] Mobility models installed")

    def _install_internet_stack(self):
        NetworkConfigurator.install_internet_stack(self.nodes)
        print(f"[BUILDER] Internet stack installed")

    def _setup_network(self):
        address = ns.Ipv4AddressHelper()
        self.interfaces = NetworkConfigurator.setup_network(self.nodes, self.config, address)
        print(f"[BUILDER] Network devices installed")

    def _setup_zsp(self):
        uav_count = len(self.config.get("uavs", []))
        for idx, zsp_conf in enumerate(self.config.get("zsps", [])):
            node = self.nodes.Get(uav_count + idx)
            zid = int(zsp_conf["id"])

            zsp = self.protocol_spec.zsp_class(
                node,
                zid,
                blockchain=self.blockchain,
                enable_blockchain=self.enable_blockchain,
                attack_model=self.attack_model,
                d2z_ack_mode=self.d2z_ack_mode,
                compute_profile=zsp_conf.get("compute_profile"),
                session_tracker=self.session_tracker,
            )

            self.zsps.append(zsp)
            node.AddApplication(zsp)
            zsp.SetStartTime(ns.Seconds(0))
            print(f"[BUILDER] ZSP-{zid} created ({self.protocol})")

    def _setup_uav(self):
        for idx, uav_conf in enumerate(self.config.get("uavs", [])):
            node = self.nodes.Get(idx)
            uid = int(uav_conf["id"])

            uav = self.protocol_spec.uav_class(
                node,
                uid,
                attack_model=self.attack_model,
                d2z_ack_mode=self.d2z_ack_mode,
                auth_trigger_config=uav_conf.get("auth_trigger"),
                link_state_config=uav_conf.get("link_state"),
                session_tracker=self.session_tracker,
            )

            self.uavs.append(uav)
            node.AddApplication(uav)
            uav.SetStartTime(ns.Seconds(0))
            print(f"[BUILDER] UAV-{uid} created ({self.protocol})")

    def _setup_user(self):
        if self.user_count > 0 and self.protocol == 'RLBA_3WAY':
            from Entity.User.RLBAUser import RLBAUser

            max_id = 0
            for u in self.config.get("uavs", []):
                max_id = max(max_id, u.get("id", 0))
            for z in self.config.get("zsps", []):
                max_id = max(max_id, z.get("id", 0))
            user_node_start_id = max_id + 1

            for i in range(self.user_count):
                user_id = f"user_{i}"
                gss_id = self.zsps[0].id if self.zsps else ""
                import hashlib
                secret = hashlib.sha256(f"RLBA_SECRET:{user_id}".encode()).hexdigest()

                user_node_id = user_node_start_id + i
                node = self.nodes.Get(user_node_id)

                user = RLBAUser(node, user_id, gss_id, secret)
                self.users.append(user)

                position = [100 + i * 50, 100, 1.0]
                MobilityFactory.install_constant(node, position)

                node.AddApplication(user)
                user.SetStartTime(ns.Seconds(0))

                user.on_connected_to_zsp(1)

                print(f"[BUILDER] User-{i} created with node ID {user_node_id} ({self.protocol})")

    def _pre_reg(self):
        for uav in self.uavs:
            reg = uav.get_registration_record()
            for zsp in self.zsps:
                zsp.RegisterUAV(reg["pid"], copy.deepcopy(reg))
        print(f"[BUILDER] Pre-registered {len(self.uavs)} UAVs ({self.protocol})")

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