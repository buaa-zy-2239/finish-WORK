from ns import ns
from Entity.UAV.PMAPUAV import PMAP_UAV
from Entity.ZSP.PMAPZSP import PMAP_ZSP
from Entity.UAV.BaseUAV import BaseUAV
from Caculator.Hash import hash_256
from BlockChain.Blockchain import Web3BlockchainAdapter
import copy

BLOCKCHAIN = Web3BlockchainAdapter()


GLOBAL_CALLBACK = []
GLOBAL_CALLBACK.append(BLOCKCHAIN)


# =============================
# 预注册
# =============================

def preregister(uav, zsp_list, real_id):

    c0 = 0.1 + real_id * 0.01
    r0 = uav.puf.generate_response(str(c0))

    pid0 = hash_256(str(real_id) + str(r0))

    uav.crp = [c0, r0]
    uav.pid = pid0

    reg = {
        "uav_id": real_id,
        "crp": [c0, r0],
        "pid": pid0
    }

    for zsp in zsp_list:
        zsp.RegisterUAV(pid0, copy.deepcopy(reg))

    print(f"[PRE-REG] UAV-{real_id} PID {pid0[:8]}")

    return pid0


# =============================
# 主函数
# =============================

def main():

    global GLOBAL_CALLBACK

    nodes = ns.NodeContainer()
    nodes.Create(3)

    stack = ns.InternetStackHelper()
    stack.Install(nodes)

    address = ns.Ipv4AddressHelper()
    address.SetBase(
        ns.Ipv4Address("10.1.1.0"),
        ns.Ipv4Mask("255.255.255.0")
    )

    channel = ns.CsmaHelper()
    channel.SetChannelAttribute("DataRate", ns.StringValue("100Mbps"))
    channel.SetChannelAttribute("Delay", ns.TimeValue(ns.NanoSeconds(6560)))

    devices = channel.Install(nodes)
    interfaces = address.Assign(devices)

    # =============================
    # 创建 ZSP
    # =============================

    zsp1 = PMAP_ZSP(nodes.Get(0), 0, blockchain=BLOCKCHAIN)
    zsp2 = PMAP_ZSP(nodes.Get(1), 1, blockchain=BLOCKCHAIN)


    # =============================
    # 创建 UAV
    # =============================

    uav = PMAP_UAV(nodes.Get(2), 1)

    nodes.Get(0).AddApplication(zsp1)
    nodes.Get(1).AddApplication(zsp2)
    nodes.Get(2).AddApplication(uav)

    zsp1.SetStartTime(ns.Seconds(0))
    zsp2.SetStartTime(ns.Seconds(0))
    uav.SetStartTime(ns.Seconds(0))

    # =============================
    # 预注册
    # =============================

    preregister(uav, [zsp1, zsp2], 1)

    # =============================
    # PID 更新 (由 ZSP1)
    # =============================


    # =============================
    # 检查 ZSP2 是否同步
    # =============================

    def check_sync():

        print("\n===== 检查 ZSP2 是否同步 PID =====")

        if uav.pid in zsp2.uav_db:

            print("[TEST] ZSP2 已同步 PID")

        else:

            print("[TEST] ZSP2 未同步 PID")

    # =============================
    # 调度任务
    # =============================
    uav._safe_schedule(8, check_sync)

    # =============================

    ns.Simulator.Stop(ns.Seconds(30))

    print("\n===== 启动仿真 =====\n")

    ns.Simulator.Run()
    ns.Simulator.Destroy()


if __name__ == "__main__":
    main()