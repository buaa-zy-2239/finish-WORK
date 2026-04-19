#!/usr/bin/env python3
"""
论文图表综合生成器：从所有实验结果中汇总数据并生成标准图表。

用法:
  python3 experiments/generate_paper_figures.py --out-dir experiments/paper_figures

输入数据源（当前仓库保留）:
  1. results_top_tier_desync/ — 去同步双臂流水线与轮次分析（主数据源）
  2. （可选）历史上由 reaggregate 生成的 statistics_summary_reaggregated.json — 若路径存在则加载；旧目录已清理时请改用 --root 指向新的结果树并先运行 reaggregate_results.py

输出图表:
  - fig1_overview_comparison.png    - 全协议多场景对比
  - fig2_loss_rate_impact.png      - 丢包率影响曲线
  - fig3_desync_boundary.png       - 边界去同步对比
  - fig4_round_curves.png          - 多轮成功率曲线（如轮次分析存在）
  - summary_table.json             - 论文可直接引用的汇总表
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
import numpy as np

ROOT = Path(__file__).resolve().parents[1]


def _mean_std(vals: List[float]) -> Tuple[float, float]:
    if not vals:
        return float("nan"), float("nan")
    return statistics.mean(vals), statistics.stdev(vals) if len(vals) > 1 else 0.0


class DataAggregator:
    """聚合多源实验数据"""

    def __init__(self):
        self.data: Dict[str, Any] = {
            "sources": [],
            "scenarios": defaultdict(lambda: defaultdict(lambda: defaultdict(dict))),
            "desync_boundary": {},
            "round_analysis": None,
        }

    def load_reaggregated(self, path: Path) -> None:
        """加载主统计汇总文件"""
        if not path.exists():
            return
        d = json.loads(path.read_text(encoding="utf-8"))
        self.data["sources"].append(str(path))
        summary = d.get("summary", {})
        for scenario, protos in summary.items():
            for proto, sizes in protos.items():
                for size_str, metrics in sizes.items():
                    if metrics is None:
                        continue
                    size = int(size_str)
                    self.data["scenarios"][scenario][proto][size] = metrics

    def load_desync_v2(self, path: Path) -> None:
        """加载desync v2激进实验数据"""
        if not path.exists():
            return
        d = json.loads(path.read_text(encoding="utf-8"))
        self.data["sources"].append(str(path))
        # desync_v2使用扁平命名，需要映射到标准scenario
        for run_tag, protos in d.get("summary", {}).items():
            # run_tag形如: task_random_n10_pmap
            scenario = "desync_multiround"  # v2是多轮激进模式
            for proto, sizes in protos.items():
                for size_str, metrics in sizes.items():
                    if metrics is None:
                        continue
                    size = int(size_str)
                    self.data["scenarios"][scenario][proto][size] = metrics

    def load_top_tier_raw(self, root: Path) -> None:
        """直接从top_tier原始result.json扫描（用于边界对比）"""
        if not root.exists():
            return
        self.data["sources"].append(str(root))

        for arm_dir in ["ack_once", "m3m4_once"]:
            arm_path = root / arm_dir
            if not arm_path.exists():
                continue

            metrics_by_config: Dict[Tuple[str, int], List[Dict]] = defaultdict(list)

            for result_file in arm_path.rglob("result.json"):
                try:
                    d = json.loads(result_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if d.get("status") != "ok":
                    continue

                proto = str(d.get("protocol", "")).upper()
                size = int(d.get("size", 0))
                auth = (
                    d.get("analysis", {})
                    .get("analyzer_summary", {})
                    .get("authentication", {})
                )
                if auth:
                    metrics_by_config[(proto, size)].append(auth)

            # 聚合统计
            for (proto, size), auths in metrics_by_config.items():
                if not auths:
                    continue
                aggregated = {}
                for key in [
                    "success_rate_percent",
                    "protocol_success_rate",
                    "channel_reliability",
                    "timeout_sessions",
                    "failed_sessions",
                    "successful_sessions",
                    "total_sessions",
                ]:
                    vals = [a.get(key) for a in auths if a.get(key) is not None]
                    if vals:
                        m, s = _mean_std(vals)
                        aggregated[key] = {"mean": round(m, 2), "std": round(s, 2), "n": len(vals)}

                scenario = f"desync_boundary_{arm_dir}"
                self.data["scenarios"][scenario][proto][size] = aggregated

    def load_round_analysis(self, root: Path) -> None:
        """加载轮次分析结果"""
        round_files = list(root.glob("round_analysis_*.json"))
        if not round_files:
            return

        round_data = {}
        for rf in round_files:
            try:
                d = json.loads(rf.read_text(encoding="utf-8"))
                arm = rf.stem.replace("round_analysis_", "")
                round_data[arm] = d
            except (OSError, json.JSONDecodeError):
                continue

        if round_data:
            self.data["round_analysis"] = round_data
            self.data["sources"].append(f"round_analysis from {root}")

    def get_scenario_list(self) -> List[str]:
        return sorted(self.data["scenarios"].keys())

    def get_protocols(self, scenario: str) -> List[str]:
        return sorted(self.data["scenarios"][scenario].keys())

    def get_metric(
        self, scenario: str, protocol: str, size: int, metric: str
    ) -> Optional[Dict]:
        return (
            self.data["scenarios"]
            .get(scenario, {})
            .get(protocol, {})
            .get(size, {})
            .get(metric)
        )


def generate_fig1_overview(agg: DataAggregator, out_path: Path) -> None:
    """图1: 多场景协议对比（主图）"""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib未安装，跳过fig1")
        return

    # 优先展示的场景
    priority_scenarios = [
        "baseline",
        "desync_attack",
        "loss_10pct",
        "loss_20pct",
        "loss_30pct",
    ]
    available = set(agg.get_scenario_list())
    scenarios = [s for s in priority_scenarios if s in available]

    if not scenarios:
        print("无可用场景数据，跳过fig1")
        return

    protocols = ["PMAP", "PMAP_ACK", "RLBA_UAV"]
    sizes = [10, 30]
    metrics = [
        ("protocol_success_rate", "Protocol Success Rate (%)"),
        ("success_rate_percent", "Overall Success Rate (%)"),
        ("channel_reliability", "Channel Reliability (%)"),
    ]

    fig, axes = plt.subplots(
        len(metrics), len(sizes), figsize=(10, 12), squeeze=False
    )

    colors = {"PMAP": "#3498db", "PMAP_ACK": "#e74c3c", "RLBA_UAV": "#2ecc71"}

    for row, (metric_key, metric_name) in enumerate(metrics):
        for col, size in enumerate(sizes):
            ax = axes[row, col]

            x_pos = range(len(scenarios))
            width = 0.25

            for p_idx, proto in enumerate(protocols):
                means, stds = [], []
                for scenario in scenarios:
                    m = agg.get_metric(scenario, proto, size, metric_key)
                    if m:
                        means.append(m["mean"])
                        stds.append(m["std"])
                    else:
                        means.append(0)
                        stds.append(0)

                offset = (p_idx - 1) * width
                ax.bar(
                    [x + offset for x in x_pos],
                    means,
                    width,
                    yerr=stds,
                    label=proto if row == 0 and col == 0 else "",
                    color=colors.get(proto, "gray"),
                    capsize=3,
                    alpha=0.8,
                )

            ax.set_xticks(x_pos)
            ax.set_xticklabels(scenarios, rotation=30, ha="right", fontsize=9)
            if row == len(metrics) - 1:
                ax.set_xlabel("Scenario", fontsize=10)
            ax.set_ylabel(metric_name, fontsize=9)
            if row == 0:
                ax.set_title(f"N={size}", fontsize=12, fontweight="bold")
            ax.grid(axis="y", alpha=0.3)
            ax.set_ylim(bottom=0, top=105)

    # 全局legend
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 0.98))

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Generated: {out_path}")


def generate_fig2_loss_curves(agg: DataAggregator, out_path: Path) -> None:
    """图2: 丢包率影响曲线"""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib未安装，跳过fig2")
        return

    loss_scenarios = ["baseline", "loss_10pct", "loss_20pct", "loss_30pct"]
    loss_rates = [0, 10, 20, 30]

    available = set(agg.get_scenario_list())
    if not any(s in available for s in loss_scenarios[1:]):
        print("无丢包实验数据，跳过fig2")
        return

    protocols = ["PMAP", "PMAP_ACK", "RLBA_UAV"]
    sizes = [10, 30]

    colors = {"PMAP": "#3498db", "PMAP_ACK": "#e74c3c", "RLBA_UAV": "#2ecc71"}
    markers = {"PMAP": "o", "PMAP_ACK": "s", "RLBA_UAV": "^"}

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    for idx, (metric, title) in enumerate(
        [("success_rate_percent", "Overall Success Rate"), ("channel_reliability", "Channel Reliability")]
    ):
        ax = axes[idx]

        for proto in protocols:
            for size in sizes:
                means, stds = [], []
                for scenario in loss_scenarios:
                    m = agg.get_metric(scenario, proto, size, metric)
                    if m:
                        means.append(m["mean"])
                        stds.append(m["std"])
                    else:
                        means.append(np.nan)
                        stds.append(0)

                means = np.array(means)
                stds = np.array(stds)

                label = f"{proto} (N={size})"
                ax.plot(
                    loss_rates,
                    means,
                    marker=markers.get(proto, "o"),
                    label=label,
                    color=colors.get(proto, "gray"),
                    linewidth=2,
                    markersize=6,
                    linestyle="-" if size == 10 else "--",
                )
                ax.fill_between(loss_rates, means - stds, means + stds, alpha=0.15)

        ax.set_xlabel("Packet Loss Rate (%)", fontsize=11)
        ax.set_ylabel(f"{title} (%)", fontsize=11)
        ax.set_title(title, fontsize=12, fontweight="bold")
        ax.legend(loc="best", fontsize=8)
        ax.grid(alpha=0.3)
        ax.set_ylim(bottom=0, top=105)

    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Generated: {out_path}")


def generate_fig3_boundary_comparison(agg: DataAggregator, out_path: Path) -> None:
    """图3: 边界去同步对比"""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib未安装，跳过fig3")
        return

    # 查找边界场景
    boundary_scenarios = [
        "desync_boundary_ack_once",
        "desync_boundary_m3m4_once",
        "desync_boundary",  # 老命名
    ]
    available = [s for s in boundary_scenarios if s in agg.get_scenario_list()]

    if not available:
        print("无边界去同步数据，跳过fig3")
        return

    fig, ax = plt.subplots(figsize=(10, 6))

    x_pos = range(len(available))
    width = 0.35

    for idx, scenario in enumerate(available):
        for p_idx, proto in enumerate(["PMAP", "PMAP_ACK"]):
            vals = []
            for size in [10, 30]:
                m = agg.get_metric(scenario, proto, size, "success_rate_percent")
                if m:
                    vals.append(m["mean"])

            if vals:
                mean_val = statistics.mean(vals)
                offset = (p_idx - 0.5) * width
                color = "#3498db" if proto == "PMAP" else "#e74c3c"
                ax.bar(idx + offset, mean_val, width, label=proto if idx == 0 else "", color=color, alpha=0.8)

    ax.set_xticks(x_pos)
    ax.set_xticklabels(available, rotation=15, ha="right")
    ax.set_ylabel("Overall Success Rate (%)", fontsize=12)
    ax.set_title("Boundary Desync: PMAP vs PMAP_ACK", fontsize=14, fontweight="bold")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    ax.set_ylim(bottom=0, top=105)

    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Generated: {out_path}")


def generate_fig4_round_curves(agg: DataAggregator, out_path: Path) -> None:
    """图4: 轮次成功率曲线（如有轮次分析数据）"""
    round_data = agg.data.get("round_analysis")
    if not round_data:
        print("无轮次分析数据，跳过fig4")
        return

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib未安装，跳过fig4")
        return

    arms = list(round_data.keys())
    if not arms:
        return

    fig, axes = plt.subplots(1, len(arms), figsize=(6 * len(arms), 5), squeeze=False)
    axes = axes[0]

    for ax_idx, (arm, data) in enumerate(round_data.items()):
        ax = axes[ax_idx]
        summary = data.get("summary", {})

        colors = {"pmap": "#3498db", "pmap_ack": "#e74c3c"}

        for proto_key in ["n10_pmap", "n10_pmap_ack", "n30_pmap", "n30_pmap_ack"]:
            block = summary.get(proto_key, {})
            rounds = block.get("rounds_pooled_across_seeds", [])
            if not rounds:
                continue

            xs = [r["round"] for r in rounds]
            ys = [r["mean_success_pct"] for r in rounds]
            lo = [r["wilson95_low_pct"] for r in rounds]
            hi = [r["wilson95_high_pct"] for r in rounds]

            size = 10 if "n10" in proto_key else 30
            proto = "PMAP" if "pmap_ack" not in proto_key else "PMAP_ACK"
            color = colors.get(proto_key.split("_")[-1], "gray")

            label = f"{proto} N={size}"
            ax.plot(xs, ys, "o-", label=label, color=color)
            ax.fill_between(xs, lo, hi, alpha=0.2, color=color)

        ax.set_xlabel("Round Index (time-ordered per UAV)", fontsize=11)
        ax.set_ylabel("Success Rate (%)", fontsize=11)
        ax.set_title(f"Arm: {arm}", fontsize=12, fontweight="bold")
        ax.legend(loc="best", fontsize=9)
        ax.grid(alpha=0.3)
        ax.set_ylim(0, 105)

    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Generated: {out_path}")


def generate_summary_table(agg: DataAggregator, out_path: Path) -> None:
    """生成论文可直接引用的汇总表（JSON格式）"""
    table = {
        "title": "D2Z Protocol Performance Summary",
        "metric_definitions": {
            "protocol_correctness_rate": "Protocol correctness: successful / (successful + failed). Excludes timeouts. Reflects pure protocol security/correctness.",
            "session_completion_rate": "Session completion: successful / total. Includes timeouts. Reflects end-to-end performance including scheduling/channel.",
            "channel_reliability": "Channel reliability: (successful + failed) / total. Proportion of sessions completing protocol flow.",
        },
        "scenarios": {},
        "sources": agg.data["sources"],
    }

    priority_order = [
        "baseline",
        "desync_attack",
        "loss_10pct",
        "loss_20pct",
        "loss_30pct",
        "desync_boundary_ack_once",
        "desync_boundary_m3m4_once",
    ]

    for scenario in priority_order:
        if scenario not in agg.data["scenarios"]:
            continue

        table["scenarios"][scenario] = {}
        for proto in ["PMAP", "PMAP_ACK", "RLBA_UAV"]:
            if proto not in agg.data["scenarios"][scenario]:
                continue

            table["scenarios"][scenario][proto] = {}
            for size in [10, 30]:
                # 优先使用新的protocol_correctness_rate，如果不存在则回退
                m_correctness = agg.get_metric(scenario, proto, size, "protocol_correctness_rate")
                m_completion = agg.get_metric(scenario, proto, size, "session_completion_rate") or \
                               agg.get_metric(scenario, proto, size, "success_rate_percent")
                
                if m_correctness or m_completion:
                    table["scenarios"][scenario][proto][f"N={size}"] = {
                        "protocol_correctness": f"{m_correctness['mean']:.1f}±{m_correctness['std']:.1f}%" if m_correctness else "N/A",
                        "session_completion": f"{m_completion['mean']:.1f}±{m_completion['std']:.1f}%" if m_completion else "N/A",
                        "n_runs": m_correctness.get("n", 3) if m_correctness else (m_completion.get("n", 3) if m_completion else 0),
                    }

    out_path.write_text(json.dumps(table, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Generated: {out_path}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate all paper figures from experiment results")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "experiments" / "paper_figures")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    # 初始化聚合器
    agg = DataAggregator()

    # 1. 可选：旧版 reaggregate 汇总（若仍存在）
    agg.load_reaggregated(
        ROOT / "experiments" / "results_statistical" / "statistics_summary_reaggregated.json"
    )

    # 2. 可选：desync v2 汇总（若仍存在）
    agg.load_desync_v2(
        ROOT / "experiments" / "results_statistical_desync_v2" / "statistics_summary.json"
    )

    # 3. top_tier 边界实验（当前主数据源）
    agg.load_top_tier_raw(ROOT / "experiments" / "results_top_tier_desync")

    # 4. 轮次分析（如有）
    agg.load_round_analysis(ROOT / "experiments" / "results_top_tier_desync")

    print(f"Loaded data from {len(agg.data['sources'])} source(s)")
    print(f"Available scenarios: {agg.get_scenario_list()}")

    # 生成图表
    generate_fig1_overview(agg, args.out_dir / "fig1_overview_comparison.png")
    generate_fig2_loss_curves(agg, args.out_dir / "fig2_loss_rate_impact.png")
    generate_fig3_boundary_comparison(agg, args.out_dir / "fig3_boundary_comparison.png")
    generate_fig4_round_curves(agg, args.out_dir / "fig4_round_curves.png")

    # 生成汇总表
    generate_summary_table(agg, args.out_dir / "summary_table.json")

    print(f"\nAll outputs saved to: {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
