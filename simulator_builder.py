import json
from ns import ns

from Mobility.mobility import MobilityFactory

from Entity.UAV.PMAPUAV import PMAP_UAV
from Entity.ZSP.PMAPZSP import PMAP_ZSP

from BlockChain.Blockchain import Web3BlockchainAdapter
import copy

BLOCKCHAIN = Web3BlockchainAdapter()


GLOBAL_CALLBACK = []
GLOBAL_CALLBACK.append(BLOCKCHAIN)


class SimulationBuilder:

    def __init__(self, config_path=None, config_dict=None):

        if config_path:
            self.config = self._load_json(config_path)
        elif config_dict:
            self.config = config_dict
        else:
            raise ValueError("Must provide config_path or config_dict")

        self.nodes = None
        self.uavs = []
        self.zsps = []

    # =========================
    # JSON加载
    # =========================

    def _load_json(self, path):

        try:
            with open(path, "r") as f:
                config = json.load(f)

            print(f"[SIM] Loaded config from {path}")
            return config

        except Exception as e:
            print(f"[SIM] JSON load error: {e}")
            raise

    # =========================
    # 主入口
    # =========================

    def run(self):

        print("[SIM] Building simulation...")
        global GLOBAL_CALLBACK
        self._create_nodes()
        self._setup_network()
        self._setup_zsp()
        self._setup_uav()
        self._pre_reg()

        duration = self.config["simulation"].get("duration", 30)

        print(f"[SIM] Running for {duration}s")

        ns.Simulator.Stop(ns.Seconds(duration))
        ns.Simulator.Run()
        ns.Simulator.Destroy()

        print("[SIM] Finished")

        return {
            "status": "completed",
            "uav_count": len(self.uavs),
            "zsp_count": len(self.zsps)
        }

    # =========================
    # 创建节点
    # =========================

    def _create_nodes(self):

        max_id = 0

        for u in self.config["uavs"]:
            max_id = max(max_id, u["id"])

        for z in self.config["zsps"]:
            max_id = max(max_id, z["id"])

        total = max_id + 1

        self.nodes = ns.NodeContainer()
        self.nodes.Create(total)

        print(f"[SIM] Created {total} nodes")

    # =========================
    # 网络
    # =========================

    def _setup_network(self):

        stack = ns.InternetStackHelper()
        stack.Install(self.nodes)

        address = ns.Ipv4AddressHelper()
        address.SetBase(
            ns.Ipv4Address("10.1.1.0"),
            ns.Ipv4Mask("255.255.255.0")
        )

        channel = ns.CsmaHelper()
        channel.SetChannelAttribute("DataRate", ns.StringValue("100Mbps"))
        channel.SetChannelAttribute("Delay", ns.TimeValue(ns.NanoSeconds(6560)))

        devices = channel.Install(self.nodes)
        interfaces = address.Assign(devices)

        print("[SIM] Network stack installed")

    # =========================
    # ZSP
    # =========================

    def _setup_zsp(self):

        for zsp_conf in self.config["zsps"]:

            node = self.nodes.Get(zsp_conf["id"])

            zsp = PMAP_ZSP(
                node,
                zsp_conf["id"],
                blockchain=BLOCKCHAIN
            )

            # 固定位置
            MobilityFactory.install_constant(
                node,
                zsp_conf["position"]
            )

            self.zsps.append(zsp)
            node.AddApplication(zsp)
            zsp.SetStartTime(ns.Seconds(0))
            print(f"[SIM] ZSP-{zsp_conf['id']} created")

    # =========================
    # UAV
    # =========================

    def _setup_uav(self):

        for uav_conf in self.config["uavs"]:

            node = self.nodes.Get(uav_conf["id"])

            # Mobility注入
            MobilityFactory.install(
                node,
                uav_conf["mobility"]
            )

            uav = PMAP_UAV(node, uav_conf["id"])

            self.uavs.append(uav)
            node.AddApplication(uav)
            uav.SetStartTime(ns.Seconds(0))
            print(f"[SIM] UAV-{uav_conf['id']} created")
    
    def _pre_reg(self):
        for uav in self.uavs:
            reg = {
                "uav_id": uav.id,
                "crp": uav.crp,
                "pid": uav.pid
            }
            for zsp in self.zsps:
                zsp.RegisterUAV(uav.pid, copy.deepcopy(reg))
        return


if __name__ == "__main__":

    builder = SimulationBuilder(config_path="/home/zhang/UAV/config.json")

    result = builder.run()

    print(result)