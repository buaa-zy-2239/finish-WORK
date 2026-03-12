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
    # 1 创建节点
    # =============================

    nodes = ns.NodeContainer()

    nodes.Create(4)

    zsp1_node = nodes.Get(0)
    zsp2_node = nodes.Get(1)

    uav1_node = nodes.Get(2)
    uav2_node = nodes.Get(3)

    # =============================
    # 2 Wifi 网络
    # =============================

    wifi = ns.WifiHelper()

    wifi.SetStandard(ns.WIFI_STANDARD_80211g)

    wifi.SetRemoteStationManager("ns3::AarfWifiManager")

    channel = ns.YansWifiChannelHelper()

    channel.SetPropagationDelay(
        "ns3::ConstantSpeedPropagationDelayModel"
    )

    channel.AddPropagationLoss(
        "ns3::FriisPropagationLossModel"
    )

    phy = ns.YansWifiPhyHelper()

    phy.SetChannel(channel.Create())

    mac = ns.WifiMacHelper()

    mac.SetType("ns3::AdhocWifiMac")

    devices = wifi.Install(phy, mac, nodes)

    # =============================
    # 3 Internet stack
    # =============================

    stack = ns.InternetStackHelper()

    stack.Install(nodes)

    address = ns.Ipv4AddressHelper()

    address.SetBase(
        ns.Ipv4Address("10.1.1.0"),
        ns.Ipv4Mask("255.255.255.0")
    )

    interfaces = address.Assign(devices)

    # =============================
    # 4 Mobility
    # =============================

    mobility = ns.MobilityHelper()

    mobility.SetMobilityModel(
        "ns3::ConstantPositionMobilityModel"
    )

    zsp_nodes = ns.NodeContainer()

    zsp_nodes.Add(zsp1_node)
    zsp_nodes.Add(zsp2_node)

    mobility.Install(zsp_nodes)

    zsp1_node.GetObject[ns.MobilityModel]().SetPosition(
        ns.Vector(0, 0, 100)
    )

    zsp2_node.GetObject[ns.MobilityModel]().SetPosition(
        ns.Vector(600, 0, 100)
    )

    # UAV mobility

    mobility2 = ns.MobilityHelper()

    mobility2.SetMobilityModel(
        "ns3::ConstantVelocityMobilityModel"
    )

    uav_nodes = ns.NodeContainer()

    uav_nodes.Add(uav1_node)
    uav_nodes.Add(uav2_node)

    mobility2.Install(uav_nodes)

    mob1 = uav1_node.GetObject[ns.ConstantVelocityMobilityModel]()
    mob1.SetPosition(ns.Vector(0, 0, 50))
    mob1.SetVelocity(ns.Vector(10, 0, 0))

    mob2 = uav2_node.GetObject[ns.ConstantVelocityMobilityModel]()
    mob2.SetPosition(ns.Vector(100, 0, 50))
    mob2.SetVelocity(ns.Vector(8, 0, 0))

    # =============================
    # 5 安装应用
    # =============================

    zsp1 = PMAP_ZSP(zsp1_node, zsp_id=0)
    zsp2 = PMAP_ZSP(zsp2_node, zsp_id=1)

    zsp1_node.AddApplication(zsp1)
    zsp2_node.AddApplication(zsp2)

    zsp1.SetStartTime(ns.Seconds(1))
    zsp2.SetStartTime(ns.Seconds(1))

    uav1 = PMAP_UAV(uav1_node, uav_id=1)
    uav2 = PMAP_UAV(uav2_node, uav_id=2)

    uav1_node.AddApplication(uav1)
    uav2_node.AddApplication(uav2)

    uav1.SetStartTime(ns.Seconds(2))
    uav2.SetStartTime(ns.Seconds(2.2))

    # =============================
    # 6 预注册
    # =============================

    pid1 = prereg(uav1, zsp1, 1)
    pid2 = prereg(uav2, zsp1, 2)

    print(f"[PRE-REG] UAV1 PID {pid1[:8]}")
    print(f"[PRE-REG] UAV2 PID {pid2[:8]}")

    # =============================
    # 7 建立连接
    # =============================

    zsp1_ip = interfaces.GetAddress(0)

    uav1.Connect(zsp1_ip, 9999)
    uav2.Connect(zsp1_ip, 9999)

    # =============================
    # 8 启动 D2Z 认证
    # =============================

    uav1.Start_D2Z_AuthLater(delay=3.0)
    uav2.Start_D2Z_AuthLater(delay=3.5)

    # =============================
    # 9 D2D 认证
    # =============================

    def start_d2d():

        print("\n===== UAV1 发起 D2D 到 UAV2 =====")

        uav1.D2D_InitiateAuth(target_uav_pid=uav2.pid)

    ns.Simulator.Schedule(ns.Seconds(4.0), start_d2d)

    # =============================
    # 10 handover 测试
    # =============================

    def handover_test():

        print("\n===== UAV1 移动到 ZSP2 区域 =====")

        zsp2_ip = interfaces.GetAddress(1)

        uav1.Connect(zsp2_ip, 9999)

        uav1.Start_D2Z_AuthLater(delay=0.5)

    ns.Simulator.Schedule(ns.Seconds(8.0), handover_test)

    # =============================

    ns.Simulator.Stop(ns.Seconds(12))

    print("\n--- 启动仿真 ---")

    ns.Simulator.Run()

    ns.Simulator.Destroy()

    # =============================
    # 结果验证
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