from ns import ns
from Entity.UAV.PMAPUAV import PMAP_UAV
from Entity.ZSP.PMAPZSP import PMAP_ZSP
from Caculator.Hash import hash_256
import copy
import json
import os
from datetime import datetime

import sys
sys.path.insert(0, '/home/zhang/UAV')
from Mobility.mobility import MobilityFactory

TOTAL_AUTH_COUNT = 100
ATTACK_START = 10
ATTACK_END = 19


def run_experiment():
    protocol_name = "PMAP"
    experiment_name = "连续攻击"
    d2z_ack_mode = False
    
    success_count = 0
    auth_attempts = 0
    experiment_results = []
    success_history = []
    
    print(f"\n{'='*60}")
    print(f"开始实验: {experiment_name} - {protocol_name}")
    print(f"{'='*60}")
    print(f"协议类型: {protocol_name}")
    print(f"攻击类型: multi")
    print(f"总认证次数: {TOTAL_AUTH_COUNT}")
    print(f"攻击轮次: {ATTACK_START}-{ATTACK_END}")
    print(f"{'='*60}\n")
    
    nodes = ns.NodeContainer()
    nodes.Create(2)
    
    stack = ns.InternetStackHelper()
    stack.Install(nodes)
    
    address = ns.Ipv4AddressHelper()
    address.SetBase(ns.Ipv4Address("10.1.1.0"), ns.Ipv4Mask("255.255.255.0"))
    
    channel = ns.CsmaHelper()
    channel.SetChannelAttribute("DataRate", ns.StringValue("100Mbps"))
    channel.SetChannelAttribute("Delay", ns.TimeValue(ns.NanoSeconds(100)))
    
    devices = channel.Install(nodes)
    interfaces = address.Assign(devices)
    
    uav_position = [50.0, 50.0, 80.0]
    zsp_position = [0.0, 0.0, 100.0]
    
    uav_mobility_conf = {
        "type": "waypoint",
        "waypoints": [[0.0, uav_position]]
    }
    MobilityFactory.install(nodes.Get(1), uav_mobility_conf)
    MobilityFactory.install_constant(nodes.Get(0), zsp_position)
    
    print(f"[移动模型] UAV固定位置: {uav_position}")
    print(f"[移动模型] ZSP固定位置: {zsp_position}")
    print(f"[信道模型] 使用CSMA信道模型，无自然丢包")
    
    attack_model = {
        "desync_attack_first_auth_only": False,
        "d2z_ack_timeout_s": 5.0,
        "max_d2z_attempts": 3,
        "d2z_retry_delay_s": 0.5,
        "intercept_m3_m4_delivery": True,
        "desync_attack_min_completed_sessions": ATTACK_START - 1,
        "desync_attack_max_completed_sessions": ATTACK_END
    }
    
    zsp = PMAP_ZSP(nodes.Get(0), 0, blockchain=None, 
                  enable_blockchain=False, attack_model=attack_model,
                  d2z_ack_mode=d2z_ack_mode)
    
    auth_trigger_config = {"allow_reauth": True, "initial_on_connect": False}
    link_state_config = {"comm_range_m": 1000.0, "drop_when_out_of_range": False, "uplink_loss_rate": 0.0}
    
    uav = PMAP_UAV(nodes.Get(1), 1, attack_model=attack_model,
                  d2z_ack_mode=d2z_ack_mode,
                  auth_trigger_config=auth_trigger_config,
                  link_state_config=link_state_config)
    uav.zsp_id = 0
    
    nodes.Get(0).AddApplication(zsp)
    nodes.Get(1).AddApplication(uav)
    
    zsp.SetStartTime(ns.Seconds(0))
    uav.SetStartTime(ns.Seconds(0))
    
    c0 = 0.1 + 1 * 0.01
    r0 = uav.puf.generate_response(c0)
    pid0 = hash_256(str(1) + str(r0))
    uav.crp = [c0, r0]
    uav.pid = pid0
    reg = {"uav_id": 1, "crp": [c0, r0], "pid": pid0}
    zsp.RegisterUAV(pid0, copy.deepcopy(reg))
    print(f"[预注册] UAV-1 PID {pid0[:8]}")
    
    zsp_addr = ns.Ipv4Address("10.1.1.1")
    
    def is_attack_round(round_num):
        return ATTACK_START <= round_num <= ATTACK_END
    
    def schedule_next_auth():
        nonlocal auth_attempts, success_count
        
        auth_attempts += 1
        current_round = auth_attempts
        attack_applied = is_attack_round(current_round)
        
        attempt_info = {
            "attempt": current_round,
            "success": False,
            "attack_applied": attack_applied,
            "uav_pid_before": uav.pid[:8],
            "timestamp": ns.Simulator.Now().GetSeconds()
        }
        
        print(f"\n[认证 #{current_round}] 开始认证" + (" [攻击]" if attack_applied else ""))
        print(f"  UAV PID: {uav.pid[:8]}")
        
        uav.authenticated = False
        uav._safe_schedule(0.1, uav.D2Z_InitiateAuth)
        
        def check_auth_result():
            nonlocal success_count
            
            if uav.authenticated:
                success_count += 1
                attempt_info["success"] = True
                print(f"[认证 #{current_round}] ✓ 认证成功")
                print(f"  新PID: {uav.pid[:8]}")
            else:
                print(f"[认证 #{current_round}] ✗ 认证失败")
            
            attempt_info["uav_pid_after"] = uav.pid[:8]
            experiment_results.append(attempt_info)
            success_history.append(success_count)
            
            if auth_attempts < TOTAL_AUTH_COUNT:
                uav._safe_schedule(1.0, schedule_next_auth)
            else:
                print(f"\n{'='*60}")
                print(f"{experiment_name} - {protocol_name} 实验完成")
                print(f"{'='*60}")
                print(f"总认证次数: {TOTAL_AUTH_COUNT}")
                print(f"成功次数: {success_count}")
                print(f"成功率: {(success_count / TOTAL_AUTH_COUNT) * 100:.2f}%")
                save_results(protocol_name, experiment_name, success_count, experiment_results, success_history)
        
        uav._safe_schedule(8.0, check_auth_result)
    
    def connect_and_start():
        print(f"[连接] UAV 连接到 ZSP: {zsp_addr}")
        uav.zsp_addr = zsp_addr
        uav.Connect(zsp_addr)
        uav.current_zsp = zsp
        uav.peer_address = zsp_addr
        schedule_next_auth()
    
    uav._safe_schedule(1.0, connect_and_start)
    
    total_sim_time = TOTAL_AUTH_COUNT * 12.0 + 30.0
    ns.Simulator.Stop(ns.Seconds(total_sim_time))
    
    print("\n启动仿真...\n")
    ns.Simulator.Run()
    ns.Simulator.Destroy()


def save_results(protocol_name, experiment_name, success_count, results, history):
    results_dir = "/home/zhang/UAV/desync_experiment_results"
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{results_dir}/results_{protocol_name}_{experiment_name}_{timestamp}.json"
    
    data = {
        "protocol": protocol_name,
        "experiment": experiment_name,
        "total_auth_count": TOTAL_AUTH_COUNT,
        "success_count": success_count,
        "success_rate": (success_count / TOTAL_AUTH_COUNT) * 100,
        "results": results,
        "success_history": history
    }
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n结果已保存到: {filename}")


if __name__ == "__main__":
    run_experiment()