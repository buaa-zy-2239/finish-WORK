from ns import ns

from Entity.UAV.PMAPUAV import PMAP_UAV
from Entity.ZSP.PMAPZSP import PMAP_ZSP
from Caculator.Hash import hash_256


def prereg(uav, zsp, real_id):
    c0 = 0.1 + real_id * 0.01
    r0 = uav.puf.generate_response(str(c0))
    pid0 = hash_256(str(real_id) + str(r0))
    uav.crp = [c0, r0]

    reg = {
        "uav_id": real_id,
        "crp": [c0, r0],
        "pid": pid0
    }
    zsp.RegisterUAV(pid0, reg)
    return pid0


def main():
    # =============================
    # 1. 创建 3 个节点
    # =============================
    nodes = ns.NodeContainer()
    nodes.Create(3)

    zsp_node = nodes.Get(0)
    uav1_node = nodes.Get(1)
    uav2_node = nodes.Get(2)

    # =============================
    # 2. P2P 两条链路
    # =============================
    p2p = ns.PointToPointHelper()
    p2p.SetDeviceAttribute("DataRate", ns.StringValue("5Mbps"))
    p2p.SetChannelAttribute("Delay", ns.StringValue("2ms"))

    pair1 = ns.NodeContainer()
    pair1.Add(zsp_node)
    pair1.Add(uav1_node)

    pair2 = ns.NodeContainer()
    pair2.Add(zsp_node)
    pair2.Add(uav2_node)

    devices1 = p2p.Install(pair1)
    devices2 = p2p.Install(pair2)

    # =============================
    # 3. 协议栈
    # =============================
    stack = ns.InternetStackHelper()
    stack.Install(nodes)

    # =============================
    # 4. IP 分配（两段网段）
    # =============================
    address = ns.Ipv4AddressHelper()

    address.SetBase(ns.Ipv4Address("10.1.1.0"),
                    ns.Ipv4Mask("255.255.255.0"))
    interfaces1 = address.Assign(devices1)

    address.SetBase(ns.Ipv4Address("10.1.2.0"),
                    ns.Ipv4Mask("255.255.255.0"))
    interfaces2 = address.Assign(devices2)

    zsp_ip1 = interfaces1.GetAddress(0)
    uav1_ip = interfaces1.GetAddress(1)

    zsp_ip2 = interfaces2.GetAddress(0)
    uav2_ip = interfaces2.GetAddress(1)

    print(f"ZSP<->UAV1: {zsp_ip1} <-> {uav1_ip}")
    print(f"ZSP<->UAV2: {zsp_ip2} <-> {uav2_ip}")

    # =============================
    # 5. 安装应用
    # =============================
    zsp = PMAP_ZSP(zsp_node, zsp_id=0)
    zsp_node.AddApplication(zsp)
    zsp.SetStartTime(ns.Seconds(1.0))
    zsp.SetStopTime(ns.Seconds(20.0))

    uav1 = PMAP_UAV(uav1_node, uav_id=1)
    uav2 = PMAP_UAV(uav2_node, uav_id=2)

    uav1_node.AddApplication(uav1)
    uav2_node.AddApplication(uav2)

    uav1.SetStartTime(ns.Seconds(2.0))
    uav2.SetStartTime(ns.Seconds(2.2))

    uav1.SetStopTime(ns.Seconds(20.0))
    uav2.SetStopTime(ns.Seconds(20.0))

    # =============================
    # 6. 预注册 CRP
    # =============================
    pid1 = prereg(uav1, zsp, 1)
    pid2 = prereg(uav2, zsp, 2)

    print(f"[PRE-REG] UAV1 PID {pid1[:8]}...")
    print(f"[PRE-REG] UAV2 PID {pid2[:8]}...")

    # =============================
    # 7. 建立连接
    # =============================
    uav1.Connect(zsp_ip1, 9999)
    uav2.Connect(zsp_ip2, 9999)

    uav1.zsp_id = 0
    uav2.zsp_id = 0

    # =============================
    # 8. 抓包
    # =============================
    p2p.EnablePcapAll("pmap_d2d_capture")

    # =============================
    # 9. 调度：先 D2Z，再 D2D
    # =============================
    uav1.Start_D2Z_AuthLater(delay=3.0)
    uav2.Start_D2Z_AuthLater(delay=3.6)

    def start_d2d():
        print("\n===== UAV1 发起 D2D 到 UAV2 =====\n")
        uav1.D2D_InitiateAuth(target_uav_pid=uav2.pid)

    ns.Simulator.Schedule(ns.Seconds(4.0), start_d2d)

    # =============================
    # 10. 运行仿真
    # =============================
    ns.Simulator.Stop(ns.Seconds(5.0))

    print("\n--- 启动 ns-3 仿真 ---")
    ns.Simulator.Run()
    ns.Simulator.Destroy()

    # =============================
    # 11. 结果核验
    # =============================
    print("\n--- D2D 结果核验 ---")
    s1 = uav1.D2D_sessions.get(uav2.pid)
    s2 = uav2.D2D_sessions.get(uav1.pid)

    if s1 and s2 and s1.session_key == s2.session_key:
        print(f"SUCCESS: D2D SK = {hex(s1.session_key)}")
    else:
        print("FAILED: D2D 会话密钥不一致")


if __name__ == "__main__":
    main()
