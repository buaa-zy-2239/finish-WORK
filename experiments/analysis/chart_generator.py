"""
顶会级图表生成器 - 自动创建IEEE/ACM标准图表

支持:
- Scalability曲线 (带误差棒)
- Density热力图
- CDF分布图
- 多子图对比布局
- PDF/SVG矢量输出
"""

import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # 无头环境
import seaborn as sns
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import json

# 顶会风格设置
plt.style.use('seaborn-v0_8-paper')  # 学术论文风格
sns.set_palette("husl")

# 颜色友好方案 (色盲友好)
CB_FRIENDLY_COLORS = {
    'PMAP': '#E69F00',      # 橙色
    'PMAP_ACK': '#56B4E9',  # 天蓝
    'RLBA_UAV': '#009E73',  # 绿色
    'baseline': '#CC79A7',  # 粉红
}


class TopTierChartGenerator:
    """顶会级图表生成器"""
    
    def __init__(self, output_dir: str = "charts"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 顶会标准字体大小
        self.font_sizes = {
            'title': 14,
            'label': 12,
            'tick': 10,
            'legend': 10,
            'annotation': 9,
        }
    
    def plot_scalability_curve(
        self,
        data: Dict[str, Dict[int, Dict[str, Any]]],
        metric: str = "success_rate_percent",
        ylabel: str = "Success Rate (%)",
        title: str = "Scalability Analysis",
        filename: str = "scalability_curve",
    ) -> Path:
        """
        绘制规模可扩展性曲线 (带误差棒)
        
        Args:
            data: {protocol: {size: {mean, ci_margin, ...}}}
            metric: 要绘制的指标
        """
        fig, ax = plt.subplots(figsize=(8, 6), dpi=300)
        
        for protocol, sizes_data in data.items():
            sizes = sorted(sizes_data.keys())
            means = [sizes_data[s]["mean"] for s in sizes]
            errors = [sizes_data[s]["ci_95_margin"] for s in sizes]
            
            color = CB_FRIENDLY_COLORS.get(protocol, None)
            
            ax.errorbar(
                sizes, means, yerr=errors,
                marker='o', markersize=8,
                capsize=5, capthick=2,
                label=protocol,
                color=color,
                linewidth=2,
                elinewidth=1.5,  # 误差棒线宽
            )
        
        ax.set_xlabel("Network Size (N)", fontsize=self.font_sizes['label'])
        ax.set_ylabel(ylabel, fontsize=self.font_sizes['label'])
        ax.set_title(title, fontsize=self.font_sizes['title'], fontweight='bold')
        ax.legend(fontsize=self.font_sizes['legend'], loc='best')
        ax.grid(True, alpha=0.3, linestyle='--')
        
        # 保存为PDF (矢量图，顶会标准)
        pdf_path = self.output_dir / f"{filename}.pdf"
        svg_path = self.output_dir / f"{filename}.svg"
        png_path = self.output_dir / f"{filename}.png"
        
        plt.savefig(pdf_path, format='pdf', bbox_inches='tight')
        plt.savefig(svg_path, format='svg', bbox_inches='tight')
        plt.savefig(png_path, format='png', dpi=300, bbox_inches='tight')
        plt.close()
        
        return pdf_path
    
    def plot_density_heatmap(
        self,
        data: Dict[str, np.ndarray],  # {protocol: 2D array (density x size)}
        density_levels: List[float],
        size_levels: List[int],
        title: str = "Density Impact Analysis",
        filename: str = "density_heatmap",
    ) -> Path:
        """
        绘制密度影响热力图
        """
        n_protocols = len(data)
        fig, axes = plt.subplots(1, n_protocols, figsize=(6*n_protocols, 5), dpi=300)
        
        if n_protocols == 1:
            axes = [axes]
        
        for idx, (protocol, matrix) in enumerate(data.items()):
            ax = axes[idx]
            
            sns.heatmap(
                matrix,
                annot=True,
                fmt='.1f',
                cmap='RdYlGn',  # 红-黄-绿，直观表示好坏
                xticklabels=size_levels,
                yticklabels=density_levels,
                ax=ax,
                vmin=0,
                vmax=100,
                cbar_kws={'label': 'Success Rate (%)'},
            )
            
            ax.set_title(f"{protocol}", fontsize=self.font_sizes['label'])
            ax.set_xlabel("Network Size (N)", fontsize=self.font_sizes['tick'])
            ax.set_ylabel("Density (UAVs/km²)", fontsize=self.font_sizes['tick'])
        
        fig.suptitle(title, fontsize=self.font_sizes['title'], fontweight='bold', y=1.02)
        plt.tight_layout()
        
        pdf_path = self.output_dir / f"{filename}.pdf"
        plt.savefig(pdf_path, format='pdf', bbox_inches='tight')
        plt.close()
        
        return pdf_path
    
    def plot_latency_cdf(
        self,
        data: Dict[str, List[float]],  # {protocol: [latency values]}
        title: str = "Latency Distribution",
        filename: str = "latency_cdf",
    ) -> Path:
        """
        绘制延迟累积分布函数 (CDF)
        """
        fig, ax = plt.subplots(figsize=(8, 6), dpi=300)
        
        for protocol, latencies in data.items():
            sorted_data = np.sort(latencies)
            cdf = np.arange(1, len(sorted_data) + 1) / len(sorted_data) * 100
            
            color = CB_FRIENDLY_COLORS.get(protocol, None)
            ax.plot(sorted_data, cdf, label=protocol, color=color, linewidth=2)
        
        ax.set_xlabel("Latency (ms)", fontsize=self.font_sizes['label'])
        ax.set_ylabel("CDF (%)", fontsize=self.font_sizes['label'])
        ax.set_title(title, fontsize=self.font_sizes['title'], fontweight='bold')
        ax.legend(fontsize=self.font_sizes['legend'])
        ax.grid(True, alpha=0.3, linestyle='--')
        
        # 添加50th, 95th, 99th百分位标记
        ax.axhline(y=50, color='gray', linestyle=':', alpha=0.5, label='50th percentile')
        ax.axhline(y=95, color='gray', linestyle='--', alpha=0.5, label='95th percentile')
        
        pdf_path = self.output_dir / f"{filename}.pdf"
        plt.savefig(pdf_path, format='pdf', bbox_inches='tight')
        plt.close()
        
        return pdf_path
    
    def plot_comparison_boxplot(
        self,
        data: Dict[str, List[float]],  # {protocol: [values]}
        ylabel: str = "Metric Value",
        title: str = "Protocol Comparison",
        filename: str = "comparison_boxplot",
    ) -> Path:
        """
        绘制对比箱线图
        """
        fig, ax = plt.subplots(figsize=(8, 6), dpi=300)
        
        labels = list(data.keys())
        values = [data[k] for k in labels]
        
        # 色盲友好的颜色
        colors = [CB_FRIENDLY_COLORS.get(l, '#999999') for l in labels]
        
        bp = ax.boxplot(
            values,
            labels=labels,
            patch_artist=True,
            showmeans=True,
            meanline=True,
        )
        
        for patch, color in zip(bp['boxes'], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
        
        ax.set_ylabel(ylabel, fontsize=self.font_sizes['label'])
        ax.set_title(title, fontsize=self.font_sizes['title'], fontweight='bold')
        ax.grid(True, alpha=0.3, axis='y', linestyle='--')
        
        pdf_path = self.output_dir / f"{filename}.pdf"
        plt.savefig(pdf_path, format='pdf', bbox_inches='tight')
        plt.close()
        
        return pdf_path
    
    def plot_error_distribution(
        self,
        data: Dict[str, Dict[str, int]],  # {protocol: {error_type: count}}
        title: str = "Error Distribution",
        filename: str = "error_distribution",
    ) -> Path:
        """
        绘制错误分布饼图
        """
        # 过滤掉空数据或全零数据的协议
        valid_data = {}
        for protocol, error_data in data.items():
            # 检查是否有有效的错误数据
            values = list(error_data.values())
            # 过滤掉 NaN 值
            valid_values = [v for v in values if v is not None and not (isinstance(v, float) and np.isnan(v))]
            # 检查是否有非零值
            if any(v > 0 for v in valid_values):
                valid_data[protocol] = error_data
        
        # 如果没有有效数据，返回空路径
        if not valid_data:
            pdf_path = self.output_dir / f"{filename}.pdf"
            return pdf_path
        
        n_protocols = len(valid_data)
        fig, axes = plt.subplots(1, n_protocols, figsize=(5*n_protocols, 5), dpi=300)
        
        if n_protocols == 1:
            axes = [axes]
        
        for idx, (protocol, error_data) in enumerate(valid_data.items()):
            ax = axes[idx]
            
            labels = list(error_data.keys())
            values = list(error_data.values())
            # 过滤掉 NaN 值
            valid_values = []
            valid_labels = []
            for label, val in zip(labels, values):
                if val is not None and not (isinstance(val, float) and np.isnan(val)):
                    valid_values.append(val)
                    valid_labels.append(label)
            
            # 确保有数据可绘制
            if valid_values and any(v > 0 for v in valid_values):
                colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#c2c2f0']
                # 确保颜色数量足够
                while len(colors) < len(valid_labels):
                    colors.extend(colors)
                
                ax.pie(
                    valid_values,
                    labels=valid_labels,
                    autopct='%1.1f%%',
                    startangle=90,
                    colors=colors[:len(valid_labels)],
                    wedgeprops={'edgecolor': 'w'}
                )
                ax.axis('equal')  # 保证饼图为圆形
                ax.set_title(f"{protocol}", fontsize=self.font_sizes['label'])
            else:
                # 如果没有有效数据，显示一个空饼图
                ax.text(0.5, 0.5, 'No Errors', ha='center', va='center', fontsize=self.font_sizes['label'])
                ax.axis('off')
                ax.set_title(f"{protocol}", fontsize=self.font_sizes['label'])
        
        fig.suptitle(title, fontsize=self.font_sizes['title'], fontweight='bold', y=1.02)
        plt.tight_layout()
        
        # 保存为多种格式
        pdf_path = self.output_dir / f"{filename}.pdf"
        svg_path = self.output_dir / f"{filename}.svg"
        png_path = self.output_dir / f"{filename}.png"
        
        plt.savefig(pdf_path, format='pdf', bbox_inches='tight')
        plt.savefig(svg_path, format='svg', bbox_inches='tight')
        plt.savefig(png_path, format='png', dpi=300, bbox_inches='tight')
        plt.close()
        
        return pdf_path
    
    def plot_distance_impact(
        self,
        data: Dict[str, List[Dict[str, Any]]],  # {protocol: [{bucket, success_rate_percent}]}
        title: str = "Distance Impact Analysis",
        filename: str = "distance_impact",
    ) -> Path:
        """
        绘制距离影响折线图
        """
        fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
        
        for protocol, distance_data in data.items():
            if not distance_data:
                continue
            
            buckets = [item['bucket'] for item in distance_data]
            success_rates = [item['success_rate_percent'] for item in distance_data]
            
            color = CB_FRIENDLY_COLORS.get(protocol, None)
            
            ax.plot(
                buckets, success_rates,
                marker='o', markersize=8,
                label=protocol,
                color=color,
                linewidth=2
            )
        
        ax.set_xlabel("Distance Range (m)", fontsize=self.font_sizes['label'])
        ax.set_ylabel("Success Rate (%)", fontsize=self.font_sizes['label'])
        ax.set_title(title, fontsize=self.font_sizes['title'], fontweight='bold')
        ax.legend(fontsize=self.font_sizes['legend'], loc='best')
        ax.grid(True, alpha=0.3, linestyle='--')
        
        # 旋转 x 轴标签，避免重叠
        plt.xticks(rotation=45, ha='right')
        
        # 保存为多种格式
        pdf_path = self.output_dir / f"{filename}.pdf"
        svg_path = self.output_dir / f"{filename}.svg"
        png_path = self.output_dir / f"{filename}.png"
        
        plt.savefig(pdf_path, format='pdf', bbox_inches='tight')
        plt.savefig(svg_path, format='svg', bbox_inches='tight')
        plt.savefig(png_path, format='png', dpi=300, bbox_inches='tight')
        plt.close()
        
        return pdf_path
    
    def plot_channel_stress_comparison(
        self,
        data: Dict[str, Dict[str, float]],  # {protocol: {stress_level: success_rate}}
        title: str = "Channel Stress Comparison",
        filename: str = "channel_stress_comparison",
    ) -> Path:
        """
        绘制信道应力对比图
        """
        fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
        
        stress_levels = sorted(list(set(level for prot_data in data.values() for level in prot_data.keys())))
        
        for protocol, stress_data in data.items():
            values = [stress_data.get(level, 0) for level in stress_levels]
            
            color = CB_FRIENDLY_COLORS.get(protocol, None)
            
            ax.plot(
                stress_levels, values,
                marker='o', markersize=8,
                label=protocol,
                color=color,
                linewidth=2
            )
        
        ax.set_xlabel("Channel Stress Level", fontsize=self.font_sizes['label'])
        ax.set_ylabel("Success Rate (%)", fontsize=self.font_sizes['label'])
        ax.set_title(title, fontsize=self.font_sizes['title'], fontweight='bold')
        ax.legend(fontsize=self.font_sizes['legend'], loc='best')
        ax.grid(True, alpha=0.3, linestyle='--')
        
        # 保存为多种格式
        pdf_path = self.output_dir / f"{filename}.pdf"
        svg_path = self.output_dir / f"{filename}.svg"
        png_path = self.output_dir / f"{filename}.png"
        
        plt.savefig(pdf_path, format='pdf', bbox_inches='tight')
        plt.savefig(svg_path, format='svg', bbox_inches='tight')
        plt.savefig(png_path, format='png', dpi=300, bbox_inches='tight')
        plt.close()
        
        return pdf_path
    
    def plot_multi_metric_dashboard(
        self,
        results: Dict[str, Any],
        motion: Optional[str] = None,
        rho: Optional[int] = None,
        gm_stress: Optional[str] = None,
        title: str = "Scalability Analysis Dashboard",
        filename: str = "dashboard",
    ) -> Path:
        """
        多指标综合仪表盘 (2x2布局)
        """
        fig, axes = plt.subplots(2, 2, figsize=(14, 10), dpi=300)
        
        # 提取数据
        cells = results.get("cells", {})
        
        # 整理数据结构
        success_rate_data = {}
        duration_data = {}
        error_data = {}
        distance_data = {}
        
        # 调试信息
        print(f"\nDebug: plot_multi_metric_dashboard called with:")
        print(f"  motion: {motion}")
        print(f"  rho: {rho}")
        print(f"  gm_stress: {gm_stress}")
        print(f"  Total cells: {len(cells)}")
        
        matched_cells = 0
        
        for key, cell in cells.items():
            meta = cell.get("meta", {})
            # 根据 motion, rho, gm_stress 过滤数据
            if motion and meta.get("motion") != motion:
                continue
            if rho is not None and meta.get("rho") != rho:
                continue
            if gm_stress and meta.get("gm_stress") != gm_stress:
                continue
            
            # 调试信息
            matched_cells += 1
            print(f"  Matched cell: {key} (gm_stress: {meta.get('gm_stress')})")
            
            proto = meta.get("proto", "Unknown")
            n = meta.get("n", 0)
            
            # 成功率数据
            sr = cell.get("success_rate_percent", {})
            sr_mean = sr.get("mean", 0)
            if proto not in success_rate_data:
                success_rate_data[proto] = {}
            success_rate_data[proto][n] = sr_mean
            
            # 延迟数据
            dur = cell.get("avg_duration_seconds", {})
            dur_mean = dur.get("mean", 0)
            if proto not in duration_data:
                duration_data[proto] = {}
            duration_data[proto][n] = dur_mean
            
            # 错误数据
            if proto not in error_data:
                error_data[proto] = {
                    "Timeout": 0,
                    "Key Mismatch": 0,
                    "M1 Errors": 0,
                    "M2 Errors": 0,
                    "M3/M4 Errors": 0
                }
            error_data[proto]["Timeout"] += cell.get("timeout_sessions", 0)
            error_data[proto]["Key Mismatch"] += cell.get("key_mismatch_sessions", 0)
            errors = cell.get("errors", {})
            error_data[proto]["M1 Errors"] += errors.get("M1_errors", 0)
            error_data[proto]["M2 Errors"] += errors.get("M2_errors", 0)
            error_data[proto]["M3/M4 Errors"] += errors.get("M3_M4_errors", 0)
            
            # 距离影响数据
            if proto not in distance_data:
                distance_data[proto] = []
            distance_impact = cell.get("distance_impact", [])
            if distance_impact:
                distance_data[proto] = distance_impact
        
        # 子图1: 成功率
        ax1 = axes[0, 0]
        ax1.set_title("Success Rate vs Network Size", fontsize=self.font_sizes['label'])
        ax1.set_xlabel("Network Size (N)")
        ax1.set_ylabel("Success Rate (%)")
        ax1.grid(True, alpha=0.3, linestyle='--')
        
        for protocol, data in success_rate_data.items():
            sizes = sorted(data.keys())
            values = [data[s] for s in sizes]
            color = CB_FRIENDLY_COLORS.get(protocol, None)
            ax1.plot(sizes, values, marker='o', markersize=8, label=protocol, color=color, linewidth=2)
        ax1.legend(fontsize=self.font_sizes['legend'], loc='best')
        
        # 子图2: 延迟分布
        ax2 = axes[0, 1]
        ax2.set_title("Average Session Duration", fontsize=self.font_sizes['label'])
        ax2.set_xlabel("Network Size (N)")
        ax2.set_ylabel("Duration (s)")
        ax2.grid(True, alpha=0.3, linestyle='--')
        
        for protocol, data in duration_data.items():
            sizes = sorted(data.keys())
            values = [data[s] for s in sizes]
            color = CB_FRIENDLY_COLORS.get(protocol, None)
            ax2.plot(sizes, values, marker='o', markersize=8, label=protocol, color=color, linewidth=2)
        ax2.legend(fontsize=self.font_sizes['legend'], loc='best')
        
        # 子图3: 错误分布
        ax3 = axes[1, 0]
        ax3.set_title("Error Distribution", fontsize=self.font_sizes['label'])
        
        # 过滤掉空数据或全零数据的协议
        valid_error_data = {}
        for protocol, error_items in error_data.items():
            # 检查是否有有效的错误数据
            values = list(error_items.values())
            # 过滤掉 NaN 值
            valid_values = [v for v in values if v is not None and not (isinstance(v, float) and np.isnan(v))]
            # 检查是否有非零值
            if any(v > 0 for v in valid_values):
                valid_error_data[protocol] = error_items
        
        n_protocols = len(valid_error_data)
        if n_protocols > 0:
            if n_protocols == 1:
                protocol = list(valid_error_data.keys())[0]
                error_items = valid_error_data[protocol]
                labels = list(error_items.keys())
                values = list(error_items.values())
                # 过滤掉 NaN 值
                valid_values = []
                valid_labels = []
                for label, val in zip(labels, values):
                    if val is not None and not (isinstance(val, float) and np.isnan(val)):
                        valid_values.append(val)
                        valid_labels.append(label)
                
                # 确保有数据可绘制
                if valid_values and any(v > 0 for v in valid_values):
                    colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99', '#c2c2f0']
                    # 确保颜色数量足够
                    while len(colors) < len(valid_labels):
                        colors.extend(colors)
                    ax3.pie(valid_values, labels=valid_labels, autopct='%1.1f%%', startangle=90, colors=colors[:len(valid_labels)], wedgeprops={'edgecolor': 'w'})
                    ax3.axis('equal')
                else:
                    # 如果没有有效数据，显示一个空饼图
                    ax3.text(0.5, 0.5, 'No Errors', ha='center', va='center', fontsize=self.font_sizes['label'])
                    ax3.axis('off')
            else:
                # 对于多个协议，使用堆叠柱状图
                labels = list(valid_error_data[list(valid_error_data.keys())[0]].keys())
                x = range(len(labels))
                width = 0.8 / n_protocols
                
                for i, (protocol, error_items) in enumerate(valid_error_data.items()):
                    values = []
                    for label in labels:
                        val = error_items.get(label, 0)
                        if val is None or (isinstance(val, float) and np.isnan(val)):
                            values.append(0)
                        else:
                            values.append(val)
                    color = CB_FRIENDLY_COLORS.get(protocol, None)
                    ax3.bar([pos + i*width for pos in x], values, width=width, label=protocol, color=color)
                ax3.set_xticks([pos + width*(n_protocols-1)/2 for pos in x])
                ax3.set_xticklabels(labels, rotation=45, ha='right')
                ax3.legend(fontsize=self.font_sizes['legend'], loc='best')
        
        # 子图4: 距离影响
        ax4 = axes[1, 1]
        ax4.set_title("Distance Impact", fontsize=self.font_sizes['label'])
        ax4.set_xlabel("Distance Range (m)")
        ax4.set_ylabel("Success Rate (%)")
        ax4.grid(True, alpha=0.3, linestyle='--')
        
        for protocol, data in distance_data.items():
            if data:
                buckets = [item.get('bucket', '') for item in data]
                success_rates = [item.get('success_rate_percent', 0) for item in data]
                color = CB_FRIENDLY_COLORS.get(protocol, None)
                ax4.plot(buckets, success_rates, marker='o', markersize=8, label=protocol, color=color, linewidth=2)
        ax4.legend(fontsize=self.font_sizes['legend'], loc='best')
        plt.xticks(rotation=45, ha='right')
        
        fig.suptitle(title, fontsize=self.font_sizes['title']+2, fontweight='bold')
        plt.tight_layout()
        
        # 保存为多种格式
        pdf_path = self.output_dir / f"{filename}.pdf"
        svg_path = self.output_dir / f"{filename}.svg"
        png_path = self.output_dir / f"{filename}.png"
        
        plt.savefig(pdf_path, format='pdf', bbox_inches='tight')
        plt.savefig(svg_path, format='svg', bbox_inches='tight')
        plt.savefig(png_path, format='png', dpi=300, bbox_inches='tight')
        plt.close()
        
        return pdf_path


# 便捷函数
def generate_all_charts(results_dir: str, output_dir: str = "charts"):
    """
    从实验结果目录自动生成所有图表
    """
    gen = TopTierChartGenerator(output_dir)
    results_path = Path(results_dir)
    
    # 加载所有结果
    all_results = []
    for result_file in results_path.glob("*/result.json"):
        with open(result_file) as f:
            all_results.append(json.load(f))
    
    if not all_results:
        print(f"No results found in {results_dir}")
        return
    
    # 聚合数据
    # ... (实现数据聚合逻辑)
    
    print(f"Charts generated in {output_dir}")


if __name__ == "__main__":
    # 测试图表生成
    gen = TopTierChartGenerator()
    
    # 模拟数据
    test_data = {
        "PMAP": {
            10: {"mean": 98.5, "ci_95_margin": 2.1},
            30: {"mean": 85.2, "ci_95_margin": 3.5},
            50: {"mean": 72.8, "ci_95_margin": 4.2},
        },
        "PMAP_ACK": {
            10: {"mean": 99.2, "ci_95_margin": 1.2},
            30: {"mean": 98.5, "ci_95_margin": 1.8},
            50: {"mean": 97.1, "ci_95_margin": 2.3},
        },
    }
    
    path = gen.plot_scalability_curve(test_data)
    print(f"Test chart saved to: {path}")
