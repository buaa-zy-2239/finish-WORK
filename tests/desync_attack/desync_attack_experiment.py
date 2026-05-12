
from ns import ns
from Entity.UAV.PMAPUAV import PMAP_UAV
from Entity.ZSP.PMAPZSP import PMAP_ZSP
from Caculator.Hash import hash_256
import copy
import matplotlib.pyplot as plt
import matplotlib
import json
import os
from datetime import datetime

# 导入移动模型相关模块
import sys
sys.path.insert(0, '/home/zhang/UAV')
from Mobility.mobility import MobilityFactory

matplotlib.rcParams['font.sans-serif'] = ['Noto Sans CJK SC', 'SimHei', 'WenQuanYi Micro Hei']
matplotlib.rcParams['axes.unicode_minus'] = False

# 实验配置
TOTAL_AUTH_COUNT = 100
SINGLE_ATTACK_ROUND = 10
MULTI_ATTACK_START = 10
MULTI_ATTACK_END = 19


class DesyncExperiment:
    def __init__(self, protocol_name, experiment_name):
        self.protocol_name = protocol_name
        self.experiment_name = experiment_name
        self.d2z_ack_mode = (protocol_name == "PMAP_ACK")
        
        self.success_count = 0
        self.auth_attempts = 0
        self.experiment_results = []
        self.success_history = []
        self.uav = None
        self.zsp = None
        
    def preregister(self, uav, zsp_list, real_id):
        c0 = 0.1 + real_id * 0.01
        r0 = uav.puf.generate_response(c0)
        
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
        
        print(f"[预注册] UAV-{real_id} PID {pid0[:8]}")
        return pid0
    
    def schedule_next_auth(self, uav, zsp, attack_config):
        self.auth_attempts += 1
        
        current_round = self.auth_attempts
        attack_applied = self._check_attack_application(current_round, attack_config)
        
        attempt_info = {
            "attempt": current_round,
            "success": False,
            "attack_applied": attack_applied,
            "uav_pid_before": uav.pid[:8],
            "timestamp": ns.Simulator.Now().GetSeconds()
        }
        
        print(f"\n[认证 #{current_round}] 开始认证")
        print(f"  UAV PID: {uav.pid[:8]}")
        if attack_applied:
            print(f"  !!!! 本轮应用去同步攻击 !!!!")
        
        uav.authenticated = False
        uav._safe_schedule(0.1, uav.D2Z_InitiateAuth)
        
        def check_auth_result():
            if uav.authenticated:
                self.success_count += 1
                attempt_info["success"] = True
                print(f"[认证 #{current_round}] ✓ 认证成功")
                print(f"  新PID: {uav.pid[:8]}")
            else:
                print(f"[认证 #{current_round}] ✗ 认证失败")
            
            attempt_info["uav_pid_after"] = uav.pid[:8]
            self.experiment_results.append(attempt_info)
            self.success_history.append(self.success_count)
            
            if self.auth_attempts &lt; TOTAL_AUTH_COUNT:
                delay = 1.0
                uav._safe_schedule(delay, self.schedule_next_auth, uav, zsp, attack_config)
            else:
                print(f"\n{'='*60}")
                print(f"{self.experiment_name} - {self.protocol_name} 实验完成")
                print(f"{'='*60}")
                self._print_summary()
                self._save_results()
        
        uav._safe_schedule(8.0, check_auth_result)
    
    def _check_attack_application(self, round_num, attack_config):
        attack_type = attack_config.get("type", "none")
        
        if attack_type == "single":
            return round_num == SINGLE_ATTACK_ROUND
        elif attack_type == "multi":
            return MULTI_ATTACK_START &lt;= round_num &lt;= MULTI_ATTACK_END
        return False
    
    def _build_attack_model(self, attack_config):
        attack_type = attack_config.get("type", "none")
        
        if attack_type == "none":
            return {}
        
        # 构建攻击模型
        attack_model = {
            "desync_attack_first_auth_only": False,
            "d2z_ack_timeout_s": 5.0,
            "max_d2z_attempts": 3,
            "d2z_retry_delay_s": 0.5
        }
        
        if self.protocol_name == "PMAP":
            attack_model["intercept_m3_m4_delivery"] = True
        else:
            attack_model["intercept_d2z_ack_send"] = True
        
        # 按轮次配置攻击范围
        if attack_type == "single":
            # 单轮攻击：第10轮（需要9次成功后）
            attack_model["desync_attack_min_completed_sessions"] = SINGLE_ATTACK_ROUND - 1
            attack_model["desync_attack_max_completed_sessions"] = SINGLE_ATTACK_ROUND
        elif attack_type == "multi":
            # 连续攻击：第10-19轮
            attack_model["desync_attack_min_completed_sessions"] = MULTI_ATTACK_START - 1
            attack_model["desync_attack_max_completed_sessions"] = MULTI_ATTACK_END
        
        return attack_model
    
    def run(self, attack_config):
        print(f"\n{'='*60}")
        print(f"开始实验: {self.experiment_name} - {self.protocol_name}")
        print(f"{'='*60}")
        print(f"协议类型: {self.protocol_name}")
        print(f"攻击类型: {attack_config.get('type', 'none')}")
        print(f"总认证次数: {TOTAL_AUTH_COUNT}")
        if attack_config.get("type") == "single":
            print(f"单轮攻击轮次: {SINGLE_ATTACK_ROUND}")
        elif attack_config.get("type") == "multi":
            print(f"连续攻击轮次: {MULTI_ATTACK_START}-{MULTI_ATTACK_END}")
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
        
        # 安装移动模型 - 航点移动模型，单航点固定位置
        uav_position = [50.0, 50.0, 80.0]  # [x, y, z] 固定位置
        zsp_position = [0.0, 0.0, 100.0]
        
        # UAV使用单航点的waypoint模型，保证位置固定
        uav_mobility_conf = {
            "type": "waypoint",
            "waypoints": [
                [0.0, uav_position]  # 起始时间，起始位置，没有后续航点 = 固定
            ]
        }
        MobilityFactory.install(nodes.Get(1), uav_mobility_conf)
        
        # ZSP使用固定位置模型
        MobilityFactory.install_constant(nodes.Get(0), zsp_position)
        
        print(f"[移动模型] UAV固定位置: {uav_position}")
        print(f"[移动模型] ZSP固定位置: {zsp_position}")
        print(f"[信道模型] 使用CSMA信道模型，无自然丢包")
        
        attack_model = self._build_attack_model(attack_config)
        
        self.zsp = PMAP_ZSP(nodes.Get(0), 0, blockchain=None, 
                          enable_blockchain=False, attack_model=attack_model,
                          d2z_ack_mode=self.d2z_ack_mode)
        
        auth_trigger_config = {
            "allow_reauth": True,
            "initial_on_connect": False
        }
        
        link_state_config = {
            "comm_range_m": 1000.0,
            "drop_when_out_of_range": False,
            "uplink_loss_rate": 0.0
        }
        
        self.uav = PMAP_UAV(nodes.Get(1), 1, attack_model=attack_model,
                          d2z_ack_mode=self.d2z_ack_mode,
                          auth_trigger_config=auth_trigger_config,
                          link_state_config=link_state_config)
        self.uav.zsp_id = 0
        
        nodes.Get(0).AddApplication(self.zsp)
        nodes.Get(1).AddApplication(self.uav)
        
        self.zsp.SetStartTime(ns.Seconds(0))
        self.uav.SetStartTime(ns.Seconds(0))
        
        self.preregister(self.uav, [self.zsp], 1)
        
        def connect_and_start():
            zsp_addr = self.zsp.GetAddress()
            print(f"[连接] UAV 连接到 ZSP: {zsp_addr}")
            self.uav.zsp_addr = zsp_addr
            self.uav.Connect(zsp_addr)
            self.uav.current_zsp = self.zsp
            self.uav.peer_address = zsp_addr
            
            self.schedule_next_auth(self.uav, self.zsp, attack_config)
        
        self.uav._safe_schedule(1.0, connect_and_start)
        
        total_sim_time = TOTAL_AUTH_COUNT * 12.0 + 30.0
        ns.Simulator.Stop(ns.Seconds(total_sim_time))
        
        print("\n启动仿真...\n")
        ns.Simulator.Run()
        ns.Simulator.Destroy()
    
    def _print_summary(self):
        print(f"总认证次数: {TOTAL_AUTH_COUNT}")
        print(f"成功次数: {self.success_count}")
        print(f"失败次数: {TOTAL_AUTH_COUNT - self.success_count}")
        print(f"成功率: {(self.success_count / TOTAL_AUTH_COUNT) * 100:.2f}%")
        
        attack_rounds = [r for r in self.experiment_results if r["attack_applied"]]
        if attack_rounds:
            print(f"\n攻击轮次详情:")
            for r in attack_rounds:
                status = "✓ 成功" if r["success"] else "✗ 失败"
                print(f"  轮次 {r['attempt']}: {status}")
        
        # 分析攻击后的恢复情况
        print(f"\n攻击后恢复分析:")
        last_attack = max([r["attempt"] for r in self.experiment_results if r["attack_applied"]], default=0)
        if last_attack &gt; 0:
            post_attack = [r for r in self.experiment_results if r["attempt"] &gt; last_attack]
            if post_attack:
                post_success = sum(1 for r in post_attack if r["success"])
                post_rate = (post_success / len(post_attack)) * 100
                print(f"  攻击后剩余轮次: {len(post_attack)}")
                print(f"  攻击后成功次数: {post_success}")
                print(f"  攻击后成功率: {post_rate:.2f}%")
                
                first_recovery = next((r for r in post_attack if r["success"]), None)
                if first_recovery:
                    recovery_round = first_recovery["attempt"] - last_attack
                    print(f"  首次恢复轮次: 攻击后第 {recovery_round} 轮")
                else:
                    print(f"  !!!! 攻击后未能恢复 !!!!")
    
    def _save_results(self):
        output_dir = "desync_experiment_results"
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{output_dir}/{self.experiment_name}_{self.protocol_name}_{timestamp}.json"
        
        data = {
            "experiment_name": self.experiment_name,
            "protocol": self.protocol_name,
            "timestamp": timestamp,
            "total_auths": TOTAL_AUTH_COUNT,
            "success_count": self.success_count,
            "success_rate": (self.success_count / TOTAL_AUTH_COUNT) * 100,
            "results": self.experiment_results,
            "success_history": self.success_history
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"\n实验结果已保存至: {filename}")
        return filename


def plot_experiment_comparison(results, output_path="desync_attack_comparison.png"):
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('去同步攻击实验对比分析', fontsize=16, fontweight='bold')
    
    # 累积成功次数曲线
    ax1 = axes[0, 0]
    for name, data in results.items():
        x = list(range(1, len(data["success_history"]) + 1))
        ax1.plot(x, data["success_history"], marker='o', markersize=3, 
                label=f'{data["protocol"]} ({data["success_rate"]:.1f}%)', linewidth=2)
    
    ax1.axvline(x=SINGLE_ATTACK_ROUND, color='red', linestyle='--', linewidth=1.5, alpha=0.7, 
                label=f'单轮攻击轮次 ({SINGLE_ATTACK_ROUND})')
    ax1.axvspan(MULTI_ATTACK_START, MULTI_ATTACK_END, color='orange', alpha=0.2, 
                label=f'连续攻击区域 ({MULTI_ATTACK_START}-{MULTI_ATTACK_END})')
    
    ax1.set_xlabel('认证轮次', fontsize=12)
    ax1.set_ylabel('累积成功次数', fontsize=12)
    ax1.set_title('累积成功次数对比', fontsize=14, fontweight='bold')
    ax1.grid(True, linestyle='--', alpha=0.6)
    ax1.legend(fontsize=10, loc='upper left')
    ax1.set_xlim(0, TOTAL_AUTH_COUNT + 2)
    ax1.set_ylim(0, TOTAL_AUTH_COUNT + 2)
    
    # 成功率柱状图
    ax2 = axes[0, 1]
    protocols = [d["protocol"] for d in results.values()]
    success_rates = [d["success_rate"] for d in results.values()]
    experiment_names = [d["experiment_name"] for d in results.values()]
    
    colors = ['skyblue', 'lightcoral']
    bars = ax2.bar(range(len(protocols)), success_rates, color=colors[:len(protocols)], alpha=0.8)
    
    for i, bar in enumerate(bars):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{success_rates[i]:.1f}%',
                ha='center', va='bottom', fontsize=11)
    
    ax2.set_xlabel('协议 - 实验', fontsize=12)
    ax2.set_ylabel('成功率 (%)', fontsize=12)
    ax2.set_title('总体成功率对比', fontsize=14, fontweight='bold')
    ax2.set_xticks(range(len(protocols)))
    ax2.set_xticklabels([f"{p}\n({n})" for p, n in zip(protocols, experiment_names)], rotation=15, fontsize=10)
    ax2.grid(True, linestyle='--', alpha=0.6, axis='y')
    ax2.set_ylim(0, 105)
    
    # 单轮认证结果（成功/失败）
    ax3 = axes[1, 0]
    for name, data in results.items():
        x = [r["attempt"] for r in data["results"]]
        y = [1 if r["success"] else 0 for r in data["results"]]
        attack_mask = [r["attack_applied"] for r in data["results"]]
        
        normal_x = [xi for xi, a in zip(x, attack_mask) if not a]
        normal_y = [yi for yi, a in zip(y, attack_mask) if not a]
        attack_x = [xi for xi, a in zip(x, attack_mask) if a]
        attack_y = [yi for yi, a in zip(y, attack_mask) if a]
        
        ax3.scatter(normal_x, normal_y, alpha=0.6, s=20, 
                   label=f'{data["protocol"]} (正常)', marker='o')
        ax3.scatter(attack_x, attack_y, alpha=1.0, s=60, 
                   label=f'{data["protocol"]} (攻击)', marker='X', edgecolors='black', linewidths=1.5)
    
    ax3.axvline(x=SINGLE_ATTACK_ROUND, color='red', linestyle='--', linewidth=1.5, alpha=0.7)
    ax3.axvspan(MULTI_ATTACK_START, MULTI_ATTACK_END, color='orange', alpha=0.2)
    
    ax3.set_xlabel('认证轮次', fontsize=12)
    ax3.set_ylabel('认证结果', fontsize=12)
    ax3.set_title('逐轮认证结果', fontsize=14, fontweight='bold')
    ax3.set_yticks([0, 1])
    ax3.set_yticklabels(['失败', '成功'])
    ax3.grid(True, linestyle='--', alpha=0.6, axis='x')
    ax3.legend(fontsize=8, loc='upper right')
    ax3.set_xlim(0, TOTAL_AUTH_COUNT + 2)
    
    # 攻击后恢复分析
    ax4 = axes[1, 1]
    recovery_data = []
    
    for name, data in results.items():
        attack_rounds = [r for r in data["results"] if r["attack_applied"]]
        if not attack_rounds:
            continue
            
        last_attack = max(r["attempt"] for r in attack_rounds)
        post_attack = [r for r in data["results"] if r["attempt"] &gt; last_attack]
        
        if post_attack:
            first_success = None
            recovery_rounds = None
            current_streak = 0
            max_streak = 0
            
            for i, r in enumerate(post_attack):
                if r["success"]:
                    if first_success is None:
                        first_success = i + 1
                    current_streak += 1
                    max_streak = max(max_streak, current_streak)
                else:
                    current_streak = 0
            
            post_success_rate = sum(1 for r in post_attack if r["success"]) / len(post_attack) * 100
            recovery_data.append({
                "protocol": data["protocol"],
                "experiment": data["experiment_name"],
                "first_recovery_round": first_success,
                "max_success_streak": max_streak,
                "post_attack_success_rate": post_success_rate,
                "total_post_attack": len(post_attack)
            })
    
    if recovery_data:
        # 绘制恢复指标对比
        x_labels = [f"{d['protocol']}\n({d['experiment']})" for d in recovery_data]
        x = range(len(recovery_data))
        width = 0.25
        
        bars1 = ax4.bar([xi - width for xi in x], 
                       [d["post_attack_success_rate"] for d in recovery_data],
                       width, label='攻击后成功率', color='skyblue', alpha=0.8)
        bars2 = ax4.bar(x, 
                       [d["first_recovery_round"] if d["first_recovery_round"] else 0 for d in recovery_data],
                       width, label='首次恢复轮次', color='lightcoral', alpha=0.8)
        bars3 = ax4.bar([xi + width for xi in x], 
                       [d["max_success_streak"] for d in recovery_data],
                       width, label='最长连续成功', color='lightgreen', alpha=0.8)
        
        for i, bar in enumerate(bars1):
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height,
                    f'{recovery_data[i]["post_attack_success_rate"]:.0f}%',
                    ha='center', va='bottom', fontsize=9)
        
        for i, bar in enumerate(bars2):
            if recovery_data[i]["first_recovery_round"]:
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width()/2., height,
                        f'{recovery_data[i]["first_recovery_round"]}',
                        ha='center', va='bottom', fontsize=9)
        
        for i, bar in enumerate(bars3):
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height,
                    f'{recovery_data[i]["max_success_streak"]}',
                    ha='center', va='bottom', fontsize=9)
        
        ax4.set_xlabel('协议 - 实验', fontsize=12)
        ax4.set_ylabel('数值', fontsize=12)
        ax4.set_title('攻击后恢复能力对比', fontsize=14, fontweight='bold')
        ax4.set_xticks(x)
        ax4.set_xticklabels(x_labels, rotation=15, fontsize=10)
        ax4.grid(True, linestyle='--', alpha=0.6, axis='y')
        ax4.legend(fontsize=10)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"\n对比分析图已保存至: {output_path}")
    plt.show()


def main():
    print("="*60)
    print("去同步攻击综合实验")
    print("="*60)
    
    all_results = {}
    
    # 实验1: 单轮去同步攻击对比
    print("\n" + "="*60)
    print("实验1: 单轮去同步攻击对比")
    print("="*60)
    
    for protocol in ["PMAP", "PMAP_ACK"]:
        exp_pmap = DesyncExperiment(protocol, "单轮攻击实验")
        attack_config = {"type": "single"}
        exp_pmap.run(attack_config)
        
        all_results[f"single_{protocol}"] = {
            "experiment_name": exp_pmap.experiment_name,
            "protocol": exp_pmap.protocol_name,
            "success_rate": (exp_pmap.success_count / TOTAL_AUTH_COUNT) * 100,
            "success_history": exp_pmap.success_history,
            "results": exp_pmap.experiment_results
        }
        
        ns.Simulator.Destroy()
        ns.Simulator = None
        import gc
        gc.collect()
    
    # 实验2: 连续去同步攻击对比
    print("\n" + "="*60)
    print("实验2: 连续去同步攻击对比")
    print("="*60)
    
    for protocol in ["PMAP", "PMAP_ACK"]:
        exp_pmap = DesyncExperiment(protocol, "连续攻击实验")
        attack_config = {"type": "multi"}
        exp_pmap.run(attack_config)
        
        all_results[f"multi_{protocol}"] = {
            "experiment_name": exp_pmap.experiment_name,
            "protocol": exp_pmap.protocol_name,
            "success_rate": (exp_pmap.success_count / TOTAL_AUTH_COUNT) * 100,
            "success_history": exp_pmap.success_history,
            "results": exp_pmap.experiment_results
        }
        
        ns.Simulator.Destroy()
        ns.Simulator = None
        gc.collect()
    
    # 生成对比图表
    if all_results:
        plot_experiment_comparison(all_results)
        
        print("\n" + "="*60)
        print("实验综合总结")
        print("="*60)
        
        print("\n各实验成功率:")
        for name, data in sorted(all_results.items()):
            print(f"  {data['experiment_name']} - {data['protocol']}: {data['success_rate']:.2f}%")
        
        print(f"\n实验结果和图表已保存到 'desync_experiment_results' 目录")
        print("="*60)


if __name__ == "__main__":
    main()

