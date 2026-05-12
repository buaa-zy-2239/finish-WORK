import json
import os
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import numpy as np

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['Noto Sans CJK SC', 'WenQuanYi Micro Hei', 'WenQuanYi Zen Hei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

# 读取实验结果
def load_results(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

# 提取认证结果
def extract_auth_results(results):
    sessions = results.get('session_tracker_results', {}).get('sessions', [])
    auth_results = []
    for session in sessions:
        auth_results.append({
            'zsp_id': session['zsp_id'],
            'success': session['success'],
            'attempt': session.get('retry_count', 0) + 1
        })
    return auth_results

# 图表1：认证状态矩阵热力图（按session序列展示）
def plot_auth_matrix(disabled_results, enabled_results):
    disabled_sessions = extract_auth_results(disabled_results)
    enabled_sessions = extract_auth_results(enabled_results)

    all_zsp_ids = sorted(set(s['zsp_id'] for s in disabled_sessions + enabled_sessions))
    zsp_count = len(all_zsp_ids)
    zsp_to_col = {zid: i for i, zid in enumerate(all_zsp_ids)}

    disabled_rounds = len(disabled_sessions)
    enabled_rounds = len(enabled_sessions)

    disabled_matrix = np.zeros((disabled_rounds, zsp_count))
    for idx, session in enumerate(disabled_sessions):
        col = zsp_to_col.get(session['zsp_id'], -1)
        if col >= 0:
            disabled_matrix[idx, col] = 1 if session['success'] else -1

    enabled_matrix = np.zeros((enabled_rounds, zsp_count))
    for idx, session in enumerate(enabled_sessions):
        col = zsp_to_col.get(session['zsp_id'], -1)
        if col >= 0:
            enabled_matrix[idx, col] = 1 if session['success'] else -1

    fig_height = max(6, disabled_rounds * 0.35 + 2)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, fig_height), constrained_layout=True)

    from matplotlib.colors import ListedColormap
    cmap = ListedColormap(['#d73027', '#f0f0f0', '#1a9850'])

    im1 = ax1.imshow(disabled_matrix, cmap=cmap, aspect='auto', vmin=-1, vmax=1)
    ax1.set_title('区块链关闭', fontsize=14, fontweight='bold')
    ax1.set_xlabel('地面站ID')
    ax1.set_ylabel('认证序列')
    ax1.set_xticks(range(zsp_count))
    ax1.set_yticks(range(disabled_rounds))
    ax1.set_xticklabels([f'ZSP-{zid}' for zid in all_zsp_ids])
    ax1.set_yticklabels([str(i + 1) for i in range(disabled_rounds)])

    im2 = ax2.imshow(enabled_matrix, cmap=cmap, aspect='auto', vmin=-1, vmax=1)
    ax2.set_title('区块链开启', fontsize=14, fontweight='bold')
    ax2.set_xlabel('地面站ID')
    ax2.set_ylabel('认证序列')
    ax2.set_xticks(range(zsp_count))
    ax2.set_yticks(range(enabled_rounds))
    ax2.set_xticklabels([f'ZSP-{zid}' for zid in all_zsp_ids])
    ax2.set_yticklabels([str(i + 1) for i in range(enabled_rounds)])

    for i in range(disabled_rounds):
        for j in range(zsp_count):
            val = disabled_matrix[i, j]
            if val != 0:
                ax1.text(j, i, 'P' if val == 1 else 'F',
                         ha='center', va='center', color='white', fontsize=10, fontweight='bold')
    for i in range(enabled_rounds):
        for j in range(zsp_count):
            val = enabled_matrix[i, j]
            if val != 0:
                ax2.text(j, i, 'P' if val == 1 else 'F',
                         ha='center', va='center', color='white', fontsize=10, fontweight='bold')

    cbar = fig.colorbar(im2, ax=[ax1, ax2], shrink=0.5, ticks=[-1, 0, 1])
    cbar.ax.set_yticklabels(['失败', '无数据', '成功'])

    plt.savefig('blockchain_experiment_results/auth_matrix.png', dpi=300, bbox_inches='tight')
    plt.close()

# 图表2：移动路径认证状态图
def plot_mobility_path(disabled_results, enabled_results):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), constrained_layout=True)

    zsp_positions = {
        1: (-200, -200), 2: (-200, 0), 3: (-200, 200),
        4: (0, -200), 5: (0, 0), 6: (0, 200),
        7: (200, -200), 8: (200, 0), 9: (200, 200),
        10: (0, -400)
    }

    path_order = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1]

    all_auth_zsp_ids = set()
    for s in extract_auth_results(disabled_results) + extract_auth_results(enabled_results):
        all_auth_zsp_ids.add(s['zsp_id'])

    disabled_success = set()
    for session in extract_auth_results(disabled_results):
        if session['success']:
            disabled_success.add(session['zsp_id'])

    enabled_success = set()
    for session in extract_auth_results(enabled_results):
        if session['success']:
            enabled_success.add(session['zsp_id'])

    def draw_scene(ax, success_set, title):
        for zsp_id, (x, y) in zsp_positions.items():
            if zsp_id in all_auth_zsp_ids:
                color = '#2ca02c' if zsp_id in success_set else '#d62728'
                marker = '^'
                size = 280
            else:
                color = '#7f7f7f'
                marker = 's'
                size = 200
            ax.scatter(x, y, s=size, c=color, marker=marker, edgecolors='black', linewidths=1.5, zorder=5)
            offset_y = 25 if zsp_id != 10 else -25
            ax.text(x, y + offset_y, f'ZSP-{zsp_id}', ha='center', fontsize=9, fontweight='bold')

        for i in range(len(path_order) - 1):
            z1, z2 = path_order[i], path_order[i + 1]
            x1, y1 = zsp_positions[z1]
            x2, y2 = zsp_positions[z2]
            ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                        arrowprops=dict(arrowstyle='->', color='#555555', lw=1.5,
                                        connectionstyle='arc3,rad=0.1', linestyle='dashed'),
                        zorder=3)

        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_xlabel('X坐标')
        ax.set_ylabel('Y坐标')
        ax.set_xlim(-350, 350)
        ax.set_ylim(-500, 350)
        ax.grid(True, alpha=0.3)
        ax.set_aspect('equal')

        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor='#2ca02c', label='认证成功'),
            Patch(facecolor='#d62728', label='认证失败'),
            Patch(facecolor='#7f7f7f', label='无认证数据'),
        ]
        ax.legend(handles=legend_elements, loc='upper right', fontsize=8)

    draw_scene(ax1, disabled_success, '区块链关闭')
    draw_scene(ax2, enabled_success, '区块链开启')

    plt.savefig('blockchain_experiment_results/mobility_path.png', dpi=300, bbox_inches='tight')
    plt.close()

# 图表3：认证状态序列图
def plot_auth_sequence(disabled_results, enabled_results):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), constrained_layout=True)

    disabled_data = extract_auth_results(disabled_results)
    enabled_data = extract_auth_results(enabled_results)

    def draw_sequence(ax, data, title):
        rounds = [i + 1 for i in range(len(data))]
        zsp_ids = [s['zsp_id'] for s in data]
        successes = [s['success'] for s in data]

        for i, (zsp_id, success) in enumerate(zip(zsp_ids, successes)):
            color = '#2ca02c' if success else '#d62728'
            ax.scatter(rounds[i], zsp_id, s=120, c=color, edgecolors='black', linewidths=1.2, zorder=5)
            if i > 0:
                dx = rounds[i] - rounds[i - 1]
                dy = zsp_ids[i] - zsp_ids[i - 1]
                if abs(dx) < 1e-9 and abs(dy) > 0:
                    ax.plot([rounds[i - 1], rounds[i]], [zsp_ids[i - 1], zsp_id],
                            '-', color='gray', alpha=0.4, linewidth=0.8, zorder=2)
                elif abs(dy) < 1e-9 and abs(dx) > 0:
                    ax.plot([rounds[i - 1], rounds[i]], [zsp_ids[i - 1], zsp_id],
                            '--', color='gray', alpha=0.4, linewidth=1.0, zorder=2)
                else:
                    ax.plot([rounds[i - 1], rounds[i]], [zsp_ids[i - 1], zsp_id],
                            '-', color='gray', alpha=0.25, linewidth=0.6, zorder=2)

        first_return_zsp1 = None
        for i, zid in enumerate(zsp_ids):
            if zid == 1 and i > 0:
                first_return_zsp1 = rounds[i]
                break

        if first_return_zsp1:
            ax.axvline(x=first_return_zsp1 - 0.5, color='#1f77b4', linestyle='--',
                       linewidth=1.5, alpha=0.7)
            ax.text(first_return_zsp1 + 0.3, max(zsp_ids) - 0.3, '回归认证',
                    color='#1f77b4', fontsize=10, fontweight='bold',
                    bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))

        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_xlabel('认证序列')
        ax.set_ylabel('地面站ID')
        min_zsp = min(zsp_ids)
        max_zsp = max(zsp_ids)
        ax.set_yticks(range(min_zsp, max_zsp + 1))
        ax.set_yticklabels([f'ZSP-{i}' for i in range(min_zsp, max_zsp + 1)])
        ax.set_xlim(0.5, len(data) + 0.5)
        ax.grid(True, alpha=0.3)

        success_count = sum(1 for s in successes if s)
        total = len(successes)
        stats_text = f'成功: {success_count}/{total} ({success_count/total*100:.1f}%)'
        ax.text(0.98, 0.03, stats_text, transform=ax.transAxes,
                ha='right', va='bottom', fontsize=10,
                bbox=dict(boxstyle='round,pad=0.4', facecolor='lightyellow', alpha=0.9))

    draw_sequence(ax1, disabled_data, '区块链关闭 - 认证状态序列')
    draw_sequence(ax2, enabled_data, '区块链开启 - 认证状态序列')

    plt.savefig('blockchain_experiment_results/auth_sequence.png', dpi=300, bbox_inches='tight')
    plt.close()

# 图表4：2-ZSP 移动路径+认证时序图
def plot_2zsp_transit(disabled_results, enabled_results):
    zsp_positions = {1: -200.0, 2: 200.0}

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 7), constrained_layout=True)

    def calc_flight_time(x):
        start = -500.0
        speed = 8.0
        return abs(x - start) / speed

    def draw_transit(ax, data, title):
        sessions = extract_auth_results(data)
        for zsp_id, pos_x in zsp_positions.items():
            ax.axvline(x=pos_x, color='#1f77b4', linestyle='--', alpha=0.5, linewidth=1.5)
            ax.text(pos_x, calc_flight_time(pos_x) + 2, f'ZSP-{zsp_id}',
                    ha='center', fontsize=10, fontweight='bold', color='#1f77b4')

        for session in sessions:
            zid, success = session['zsp_id'], session['success']
            pos_x = zsp_positions.get(zid, 0)
            t = calc_flight_time(pos_x)
            color = '#2ca02c' if success else '#d62728'
            marker = 'o' if success else 'X'
            edge = 'black' if success else color
            ax.scatter(pos_x, t, s=160, c=color, marker=marker,
                       edgecolors=edge, linewidths=1.5, zorder=5)
            offset_y = 3 if zid == 1 else -3
            status_str = 'OK' if success else 'FAIL'
            ax.text(pos_x + 25, t + offset_y, f'ZSP-{zid}\n{status_str}',
                    ha='left', fontsize=8, fontweight='bold',
                    bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))

        xs = [-500, -400, -300, -200, -100, 0, 100, 200, 300, 400, 500]
        ts = [calc_flight_time(x) for x in xs]
        ax.plot(xs, ts, '-', color='gray', alpha=0.4, linewidth=1.5, label='UAV路径')
        ax.axvspan(-500, 0, alpha=0.05, color='#1f77b4')
        ax.axvspan(0, 500, alpha=0.05, color='#ff7f0e')

        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_xlabel('X 坐标 (m)')
        ax.set_ylabel('时间 (s)')
        ax.set_xlim(-550, 550)
        ax.set_ylim(0, max(ts) + 10)
        ax.grid(True, alpha=0.3)

        from matplotlib.patches import Patch
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], marker='o', color='w', markerfacecolor='#2ca02c', markersize=10, label='认证成功'),
            Line2D([0], [0], marker='X', color='#d62728', markersize=10, label='认证失败'),
            Patch(facecolor='#1f77b4', alpha=0.08, label='ZSP-1 覆盖区'),
            Patch(facecolor='#ff7f0e', alpha=0.08, label='ZSP-2 覆盖区'),
        ]
        ax.legend(handles=legend_elements, loc='upper right', fontsize=8)

    draw_transit(ax1, disabled_results, '区块链关闭 - 穿越认证过程')
    draw_transit(ax2, enabled_results, '区块链开启 - 穿越认证过程')

    plt.savefig('blockchain_experiment_results/2zsp_transit.png', dpi=300, bbox_inches='tight')
    plt.close()


# 图表5：2-ZSP 认证结果对比柱状图
def plot_2zsp_comparison(disabled_results, enabled_results):
    disabled_sessions = extract_auth_results(disabled_results)
    enabled_sessions = extract_auth_results(enabled_results)

    def count_by_zsp(sessions):
        from collections import Counter
        success = Counter()
        fail = Counter()
        for s in sessions:
            if s['success']:
                success[s['zsp_id']] += 1
            else:
                fail[s['zsp_id']] += 1
        return success, fail

    d_succ, d_fail = count_by_zsp(disabled_sessions)
    e_succ, e_fail = count_by_zsp(enabled_sessions)

    all_zsp_ids = sorted(set(list(d_succ.keys()) + list(d_fail.keys()) +
                             list(e_succ.keys()) + list(e_fail.keys())))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8, 5), constrained_layout=True)

    x = np.arange(len(all_zsp_ids))
    width = 0.35

    for ax, title, succ, fail in [
        (ax1, '区块链关闭', d_succ, d_fail),
        (ax2, '区块链开启', e_succ, e_fail)
    ]:
        succ_vals = [succ.get(zid, 0) for zid in all_zsp_ids]
        fail_vals = [fail.get(zid, 0) for zid in all_zsp_ids]

        ax.bar(x - width / 2, succ_vals, width, label='成功', color='#2ca02c')
        ax.bar(x + width / 2, fail_vals, width, label='失败', color='#d62728')

        for i, (s, f) in enumerate(zip(succ_vals, fail_vals)):
            total = s + f
            if total > 0:
                rate = s / total * 100
                ax.text(x[i], total + 0.15, f'{rate:.0f}%', ha='center', fontsize=10, fontweight='bold')

        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_xlabel('地面站ID')
        ax.set_ylabel('认证次数')
        ax.set_xticks(x)
        ax.set_xticklabels([f'ZSP-{zid}' for zid in all_zsp_ids])
        ax.set_ylim(0, max(max(succ_vals + fail_vals) + 1, 3))
        ax.legend(fontsize=9)
        ax.grid(True, alpha=0.3, axis='y')

    plt.savefig('blockchain_experiment_results/2zsp_comparison.png', dpi=300, bbox_inches='tight')
    plt.close()


# 主函数
def main():
    # 加载10-ZSP实验结果
    disabled_10zsp = load_results('blockchain_experiment_results/exp3_10zsp_disabled_20260511_203822.json')
    enabled_10zsp = load_results('blockchain_experiment_results/exp4_10zsp_enabled_20260511_203902.json')

    # 加载2-ZSP实验结果
    disabled_2zsp = load_results('blockchain_experiment_results/exp1_2zsp_disabled_20260511_192812.json')
    enabled_2zsp = load_results('blockchain_experiment_results/exp2_2zsp_enabled_20260511_192841.json')

    # 创建10-ZSP图表
    plot_auth_matrix(disabled_10zsp, enabled_10zsp)
    plot_mobility_path(disabled_10zsp, enabled_10zsp)
    plot_auth_sequence(disabled_10zsp, enabled_10zsp)

    # 创建2-ZSP图表
    plot_2zsp_transit(disabled_2zsp, enabled_2zsp)
    plot_2zsp_comparison(disabled_2zsp, enabled_2zsp)

    print("图表已生成，保存在 blockchain_experiment_results/ 目录中")

if __name__ == "__main__":
    main()