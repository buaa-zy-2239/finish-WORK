# scenario_steps.py
from ns import ns
from Entity.UAV.PMAPUAV import PMAP_UAV
from Entity.ZSP.PMAPZSP import PMAP_ZSP
from Caculator.Hash import hash_256


# =============================
# 1. 构建拓扑
# =============================
def build_topology(cfg):
    nodes = ns.NodeContainer()
    nodes.Create(cfg["uav_count"] + cfg["zsp_count"])
    uav_count=int(cfg["uav_count"])
    zsp_count=int(cfg["zsp_count"])
    p2p = ns.PointToPointHelper()
    p2p.SetDeviceAttribute("DataRate", ns.StringValue(cfg["datarate"]))
    p2p.SetChannelAttribute("Delay", ns.StringValue(cfg["delay"]))

    devices = p2p.Install(nodes)

    stack = ns.InternetStackHelper()
    stack.Install(nodes)

    address = ns.Ipv4AddressHelper()
    address.SetBase(ns.Ipv4Address("10.1.1.0"),
                    ns.Ipv4Mask("255.255.255.0"))
    interfaces = address.Assign(devices)

    return {
        "nodes": nodes,
        "interfaces": interfaces,
        "uav_count": uav_count,
        "zsp_count": zsp_count
    }


# =============================
# 2. 加载实体（协议相关）
# =============================
def load_entities(cfg, topo):
    zsp_ips = []
    zsp_nodes = []
    uav_ips = []
    uav_nodes = []
    for i in range(topo["zsp_count"]):
        zsp_nodes.append(topo["nodes"].Get(i))
        zsp_ips.append(topo["interfaces"].GetAddress(i))
    for i in range(topo["uav_count"]):
        uav_nodes.append(topo["nodes"].Get(i+topo["zsp_count"]))
        uav_ips.append(topo["interfaces"].GetAddress(i+topo["zsp_count"]))

    zsp_ip = zsp_ips[0]
    uav_ip = uav_ips[0]
    zsp_node = zsp_nodes[0]
    uav_node = uav_nodes[0]

    print(f"ZSP IP: {zsp_ip}")
    print(f"UAV IP: {uav_ip}")

    zsp_app = PMAP_ZSP(zsp_node, 0)
    zsp_node.AddApplication(zsp_app)
    zsp_app.SetStartTime(ns.Seconds(1.0))
    zsp_app.SetStopTime(ns.Seconds(cfg["stop_time"]))

    uav_app = PMAP_UAV(uav_node, 1)
    uav_node.AddApplication(uav_app)
    uav_app.SetStartTime(ns.Seconds(2.0))
    uav_app.SetStopTime(ns.Seconds(cfg["stop_time"]))

    return {
        "zsp": zsp_app,
        "uav": uav_app,
        "zsp_ip": zsp_ip
    }


# =============================
# 3. 预注册 CRP
# =============================
def pre_register(cfg, entities):
    uav_app = entities["uav"]
    zsp_app = entities["zsp"]

    initial_c = 0.1
    initial_r = uav_app.puf.generate_response(str(initial_c))
    initial_pid = hash_256(str(1) + str(initial_r))

    uav_app.crp = [initial_c, initial_r]

    reg_info = {
        "uav_id": 1,
        "crp": [initial_c, initial_r],
        "pid": initial_pid
    }

    zsp_app.RegisterUAV(initial_pid, reg_info)
    print(f"[PRE-REG] PID {initial_pid[:8]}... 已注册至 ZSP")


# =============================
# 4. 建立连接
# =============================
def bind_links(cfg, entities):
    entities["uav"].Connect(entities["zsp_ip"], 9999)
    entities["uav"].zsp_id = 0


# =============================
# 5. 安排认证启动
# =============================
def schedule_auth(cfg, entities):
    entities["uav"].Start_D2Z_AuthLater(delay=cfg["auth_delay"])


# =============================
# 6. 运行仿真
# =============================
def run_simulation(cfg):
    ns.Simulator.Stop(ns.Seconds(cfg["stop_time"]))
    print("\n--- 启动 ns-3 仿真 ---")
    ns.Simulator.Run()
    ns.Simulator.Destroy()


# =============================
# 7. 验证结果
# =============================
def verify_result(entities):
    uav = entities["uav"]
    zsp = entities["zsp"]

    print("\n--- 认证结果核验 ---")
    if uav.session_key and zsp.D2Z_sessions.get(uav.pid) and zsp.D2Z_sessions[uav.pid].session_key:
        if uav.session_key == zsp.D2Z_sessions[uav.pid].session_key:
            print(f"SUCCESS: SK = {hex(uav.session_key)}")
        else:
            print("FAILED: 会话密钥不一致")
    else:
        print("FAILED: 协议未完成，会话密钥为空")
