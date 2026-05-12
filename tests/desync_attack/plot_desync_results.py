import json
import os
import matplotlib.pyplot as plt
import matplotlib
import matplotlib.font_manager as fm

fonts = [f.name for f in fm.fontManager.ttflist]
if 'Noto Sans CJK SC' in fonts:
    matplotlib.rcParams['font.sans-serif'] = ['Noto Sans CJK SC', 'DejaVu Sans']
elif 'WenQuanYi Micro Hei' in fonts:
    matplotlib.rcParams['font.sans-serif'] = ['WenQuanYi Micro Hei', 'DejaVu Sans']
elif 'SimHei' in fonts:
    matplotlib.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans']
else:
    matplotlib.rcParams['font.sans-serif'] = ['DejaVu Sans']
matplotlib.rcParams['axes.unicode_minus'] = False

def load_results():
    results_dir = "/home/zhang/UAV/desync_experiment_results"
    results = {}
    
    if not os.path.exists(results_dir):
        print(f"错误：结果目录 {results_dir} 不存在")
        return results
    
    for filename in os.listdir(results_dir):
        if filename.startswith("results_") and filename.endswith(".json"):
            filepath = os.path.join(results_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    key = f"{data['protocol']}_{data['experiment']}"
                    results[key] = data
            except Exception as e:
                print(f"加载文件 {filename} 失败: {e}")
    
    return results

def plot_single_attack(results):
    fig, ax = plt.subplots(figsize=(12, 6))
    
    attack_round = 10
    
    pmap_data = results.get("PMAP_单轮攻击")
    pmap_ack_data = results.get("PMAP_ACK_单轮攻击")
    
    if pmap_data:
        rounds = range(1, len(pmap_data["success_history"]) + 1)
        ax.plot(rounds, pmap_data["success_history"], label='PMAP', 
                color='#1f77b4', linewidth=2, marker='o', markersize=3)
        
        attack_val = pmap_data["success_history"][attack_round-1]
        ax.scatter(attack_round, attack_val, color='#1f77b4', s=100, 
                   marker='x', linewidth=3, label=f'PMAP攻击点')
    
    if pmap_ack_data:
        rounds = range(1, len(pmap_ack_data["success_history"]) + 1)
        ax.plot(rounds, pmap_ack_data["success_history"], label='PMAP_ACK', 
                color='#ff7f0e', linewidth=2, marker='s', markersize=3)
        
        attack_val = pmap_ack_data["success_history"][attack_round-1]
        ax.scatter(attack_round, attack_val, color='#ff7f0e', s=100, 
                   marker='x', linewidth=3, label=f'PMAP_ACK攻击点')
    
    ax.axvline(x=attack_round, color='red', linestyle='--', linewidth=1.5)
    ax.text(attack_round + 1, 95, f'攻击点\n(第{attack_round}轮)', 
            color='red', fontsize=10, ha='left', va='top')
    
    ax.set_xlabel('认证次数', fontsize=12)
    ax.set_ylabel('累计成功认证次数', fontsize=12)
    ax.set_title('单轮攻击实验对比 - PMAP vs PMAP_ACK', fontsize=14)
    ax.legend(fontsize=10)
    ax.grid(True, linestyle='--', alpha=0.7)
    ax.set_xlim(0, 101)
    ax.set_ylim(0, 100)
    
    plt.tight_layout()
    plt.savefig('/home/zhang/UAV/single_attack_comparison.png', dpi=300, bbox_inches='tight')
    print("单轮攻击对比图已保存: single_attack_comparison.png")
    plt.show()

def plot_multi_attack(results):
    fig, ax = plt.subplots(figsize=(12, 6))
    
    attack_start = 10
    attack_end = 19
    
    pmap_data = results.get("PMAP_连续攻击")
    pmap_ack_data = results.get("PMAP_ACK_连续攻击")
    
    if pmap_data:
        rounds = range(1, len(pmap_data["success_history"]) + 1)
        ax.plot(rounds, pmap_data["success_history"], label='PMAP', 
                color='#1f77b4', linewidth=2, marker='o', markersize=3)
        
        start_val = pmap_data["success_history"][attack_start-1]
        end_val = pmap_data["success_history"][attack_end-1]
        ax.scatter(attack_start, start_val, color='#1f77b4', s=100, 
                   marker='x', linewidth=3)
        ax.scatter(attack_end, end_val, color='#1f77b4', s=100, 
                   marker='x', linewidth=3)
    
    if pmap_ack_data:
        rounds = range(1, len(pmap_ack_data["success_history"]) + 1)
        ax.plot(rounds, pmap_ack_data["success_history"], label='PMAP_ACK', 
                color='#ff7f0e', linewidth=2, marker='s', markersize=3)
        
        start_val = pmap_ack_data["success_history"][attack_start-1]
        end_val = pmap_ack_data["success_history"][attack_end-1]
        ax.scatter(attack_start, start_val, color='#ff7f0e', s=100, 
                   marker='x', linewidth=3)
        ax.scatter(attack_end, end_val, color='#ff7f0e', s=100, 
                   marker='x', linewidth=3)
    
    ax.axvspan(attack_start, attack_end, color='red', alpha=0.2)
    ax.text((attack_start + attack_end) / 2, 95, f'攻击区间\n(第{attack_start}-{attack_end}轮)', 
            color='red', fontsize=10, ha='center', va='top')
    
    ax.set_xlabel('认证次数', fontsize=12)
    ax.set_ylabel('累计成功认证次数', fontsize=12)
    ax.set_title('连续攻击实验对比 - PMAP vs PMAP_ACK', fontsize=14)
    ax.legend(fontsize=10)
    ax.grid(True, linestyle='--', alpha=0.7)
    ax.set_xlim(0, 101)
    ax.set_ylim(0, 100)
    
    plt.tight_layout()
    plt.savefig('/home/zhang/UAV/multi_attack_comparison.png', dpi=300, bbox_inches='tight')
    print("连续攻击对比图已保存: multi_attack_comparison.png")
    plt.show()

def print_summary(results):
    print("\n" + "="*60)
    print("实验结果汇总")
    print("="*60)
    
    for key in ["PMAP_单轮攻击", "PMAP_ACK_单轮攻击", "PMAP_连续攻击", "PMAP_ACK_连续攻击"]:
        if key in results:
            data = results[key]
            print(f"\n{key}:")
            print(f"  总认证次数: {data['total_auth_count']}")
            print(f"  成功次数: {data['success_count']}")
            print(f"  成功率: {data['success_rate']:.2f}%")
            
            if "单轮" in key:
                attack_round = 10
                attack_result = data['results'][attack_round-1]
                print(f"  第{attack_round}轮攻击结果: {'成功' if attack_result['success'] else '失败'}")
                
                post_attack_success = sum(1 for r in data['results'][attack_round:] if r['success'])
                print(f"  攻击后成功次数: {post_attack_success}")
            else:
                attack_start, attack_end = 10, 19
                attack_success = sum(1 for r in data['results'][attack_start-1:attack_end] if r['success'])
                print(f"  攻击期间(10-19轮)成功次数: {attack_success}")
                
                post_attack_success = sum(1 for r in data['results'][attack_end:] if r['success'])
                print(f"  攻击后成功次数: {post_attack_success}")

def main():
    results = load_results()
    
    if not results:
        print("未找到实验结果文件")
        return
    
    print_summary(results)
    
    plot_single_attack(results)
    plot_multi_attack(results)

if __name__ == "__main__":
    main()