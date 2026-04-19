#!/usr/bin/env python3
"""
读取 round_analysis_*.json，仅生成去同步叙事三张图（Fig 1–3）：
  Fig 1: PMAP_ACK / 持续 ACK（ack_once）
  Fig 2: PMAP_ACK / 持续 M3M4（m3m4_sustained）
  Fig 3: PMAP vs PMAP_ACK（可选 RLBA_UAV）/ 单次 M3M4（m3m4_once）

用法:
  python3 experiments/top_tier_desync/plot_top_tier_figures.py \\
    --results-root experiments/results_desync_microscopic
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib

matplotlib.use("Agg")  # 非交互式后端
import matplotlib.pyplot as plt
import numpy as np

# 顶会标准配色方案（支持色盲友好和黑白打印）
COLORS = {
    "PMAP": "#1f77b4",  # 蓝色
    "PMAP_ACK": "#ff7f0e",  # 橙色
    "RLBA_UAV": "#2ca02c",  # 绿色（与论文图脚本一致）
    "ATTACK": "#d62728",  # 红色
    "GRID": "#cccccc",  # 浅灰网格
}

MARKERS = {
    "PMAP": "o",
    "PMAP_ACK": "s",
    "RLBA_UAV": "^",
}

LINESTYLES = {
    "PMAP": "-",
    "PMAP_ACK": "--",
    "RLBA_UAV": "-.",
}


def setup_academic_style() -> None:
    """配置 matplotlib 顶会标准样式"""
    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": [
                "DejaVu Sans",
                "Arial",
                "Helvetica",
                "Liberation Sans",
            ],
            "font.size": 10,
            "axes.titlesize": 14,
            "axes.labelsize": 12,
            "xtick.labelsize": 10,
            "ytick.labelsize": 10,
            "legend.fontsize": 10,
            "figure.dpi": 100,
            "savefig.dpi": 300,
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.02,
            "axes.grid": True,
            "grid.alpha": 0.3,
            "grid.linestyle": ":",
            "grid.color": COLORS["GRID"],
            "axes.linewidth": 1.0,
            "lines.linewidth": 2.0,
            "lines.markersize": 6,
            "lines.markeredgewidth": 1.5,
            "errorbar.capsize": 3,
        }
    )


def _discover_sizes(data: dict, arms: List[str]) -> List[int]:
    sizes: set[int] = set()
    for arm in arms:
        summ = (data.get(arm) or {}).get("summary") or {}
        for k in summ:
            m = re.match(r"^n(\d+)_(pmap_ack|pmap|rlba_uav)$", k, re.I)
            if m:
                sizes.add(int(m.group(1)))
    return sorted(sizes)


def get_smart_xticks(max_round: int, max_ticks: int = 12) -> List[int]:
    """智能生成横坐标刻度，避免标签重叠。"""
    if max_round <= max_ticks:
        return list(range(1, max_round + 1, 1))

    step_candidates = [5, 10, 15, 20, 25, 30, 50, 100]
    for step in step_candidates:
        n_ticks = (max_round // step) + 1
        if n_ticks <= max_ticks:
            return list(range(1, max_round + 1, step))

    log_ticks = np.logspace(0, np.log10(max_round), num=max_ticks)
    return [int(round(t)) for t in log_ticks]


def _plot_cumulative_narrative(
    fig_dir: Path,
    base_filename: str,
    suptitle: str,
    size: int,
    arms_protocols: List[Tuple[str, str]],
    data: dict,
) -> None:
    """
    叙事专用累积成功图：纵坐标=累积成功次数，横坐标=认证轮次。
    arms_protocols: 要叠加显示的 (arm, protocol) 列表，支持跨臂对比。
    """
    fig, ax = plt.subplots(figsize=(8, 5))

    attack_rounds_global: set[int] = set()
    max_round = 0

    for arm, proto in arms_protocols:
        
        payload = data.get(arm) or {}
        summ = payload.get("summary") or {}
        key = f"n{size}_{proto.lower()}"
        block = summ.get(key) or {}
        rounds = block.get("rounds_pooled_across_seeds") or []

        if not rounds:
            continue

        xs = [r["round"] for r in rounds]
        ys_cum = [r.get("cumulative_successes", 0) for r in rounds]
        max_round = max(max_round, max(xs))

        attack_rounds = [r["round"] for r in rounds if r.get("is_attack_round")]
        attack_rounds_global.update(attack_rounds)

        color = COLORS.get(proto, "#333333")
        marker = MARKERS.get(proto, "o")
        linestyle = LINESTYLES.get(proto, "-")

        label = f"{proto} ({arm.replace('_', ' ')})"
        if proto == "PMAP_ACK" and "ack_once" in arm:
            label = f"{proto} (ack sustained)"
        ax.plot(
            xs,
            ys_cum,
            linestyle=linestyle,
            marker=marker,
            markersize=5,
            markevery=max(1, len(xs) // 15),
            color=color,
            linewidth=2,
            label=label,
            markerfacecolor="white",
            markeredgewidth=1.5,
        )

    if attack_rounds_global:
        import matplotlib.transforms as transforms

        blend_transform = transforms.blended_transform_factory(
            ax.transData, ax.transAxes
        )
        y_marker = 0.0
        y_label = -0.027

        sorted_rounds = sorted(attack_rounds_global)
        intervals = []
        start = sorted_rounds[0]
        end = sorted_rounds[0]
        for r in sorted_rounds[1:]:
            if r == end + 1:
                end = r
            else:
                intervals.append((start, end))
                start = r
                end = r
        intervals.append((start, end))

        for start, end in intervals:
            ax.plot(
                [start, end],
                [y_marker, y_marker],
                color=COLORS["ATTACK"],
                linewidth=4,
                solid_capstyle="butt",
                zorder=5,
                transform=blend_transform,
                clip_on=False,
            )
            ax.scatter(
                [start],
                [y_marker],
                marker="o",
                s=50,
                color=COLORS["ATTACK"],
                zorder=6,
                edgecolors="white",
                linewidths=1.5,
                transform=blend_transform,
                clip_on=False,
            )
            ax.scatter(
                [end],
                [y_marker],
                marker="o",
                s=50,
                color=COLORS["ATTACK"],
                zorder=6,
                edgecolors="white",
                linewidths=1.5,
                transform=blend_transform,
                clip_on=False,
            )
            label_offset = 0.8 if end == start else 0
            ax.annotate(
                f"{start}",
                xy=(start + label_offset, y_label),
                xycoords=blend_transform,
                fontsize=10,
                ha="center",
                va="top",
                color=COLORS["ATTACK"],
                fontweight="bold",
                clip_on=False,
            )
            if end != start:
                ax.annotate(
                    f"{end}",
                    xy=(end, y_label),
                    xycoords=blend_transform,
                    fontsize=10,
                    ha="center",
                    va="top",
                    color=COLORS["ATTACK"],
                    fontweight="bold",
                    clip_on=False,
                )
        fig.subplots_adjust(bottom=0.12)

    xticks = get_smart_xticks(max_round)
    ax.set_xticks(xticks)
    ax.set_xlabel("Authentication Round Index", fontweight="medium")
    ax.set_ylabel("Cumulative Successful Authentications", fontweight="medium")
    ax.set_title(suptitle, fontsize=12, pad=10)
    ax.set_ylim(bottom=0)

    handles, labels = ax.get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    ax.legend(
        by_label.values(),
        by_label.keys(),
        loc="lower right",
        bbox_to_anchor=(1.0, 0.15),
        frameon=True,
        fancybox=True,
        edgecolor="gray",
        facecolor="white",
        framealpha=0.9,
    )
    ax.grid(True, linestyle="--", alpha=0.4, linewidth=0.5)
    ax.set_axisbelow(True)

    for ext in ("pdf", "png"):
        fn = fig_dir / f"{base_filename}.{ext}"
        fig.savefig(fn, format=ext, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {fig_dir / base_filename}.pdf", flush=True)


def plot_narrative_figures(fig_dir: Path, sizes_all: List[int], data: dict) -> None:
    """
    三张叙事图：
    1. PMAP_ACK 面对持续 ACK 攻击（ack_once 臂）
    2. PMAP_ACK 面对持续 M3M4 攻击（m3m4_sustained 臂）
    3. PMAP+PMAP_ACK(+RLBA) 面对 M3M4_once
    """
    for size in sizes_all:
        if "ack_once" in data:
            _plot_cumulative_narrative(
                fig_dir,
                f"fig1_ack_sustained_n{size}",
                f"Fig 1: PMAP_ACK under sustained ACK suppression | N={size}",
                size,
                [("ack_once", "PMAP_ACK")],
                data,
            )

        if "m3m4_sustained" in data:
            _plot_cumulative_narrative(
                fig_dir,
                f"fig2_m3m4_sustained_n{size}",
                f"Fig 2: PMAP_ACK under sustained M3/M4 interception | N={size}",
                size,
                [("m3m4_sustained", "PMAP_ACK")],
                data,
            )

        if "m3m4_once" in data:
            arms_protos = [
                ("m3m4_once", "PMAP"),
                ("m3m4_once", "PMAP_ACK"),
            ]
            summ = data["m3m4_once"].get("summary") or {}
            if summ.get(f"n{size}_rlba_uav"):
                arms_protos.append(("m3m4_once", "RLBA_UAV"))
            _plot_cumulative_narrative(
                fig_dir,
                f"fig3_m3m4_once_n{size}",
                f"Fig 3: PMAP vs PMAP_ACK under single M3/M4 interception | N={size}",
                size,
                arms_protos,
                data,
            )


def _discover_arms_from_root(root: Path) -> List[str]:
    arms: List[str] = []
    for p in sorted(root.glob("round_analysis_*.json")):
        stem = p.stem
        if stem.startswith("round_analysis_"):
            arms.append(stem[len("round_analysis_") :])
    return arms


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-root", type=Path, required=True)
    ap.add_argument(
        "--arms",
        type=str,
        default="",
        help="逗号分隔臂名；默认识别 results-root 下全部 round_analysis_*.json",
    )
    args = ap.parse_args()

    root = args.results_root.resolve()
    fig_dir = root / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    setup_academic_style()

    if args.arms.strip():
        arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    else:
        arms = _discover_arms_from_root(root)

    if not arms:
        print("no round_analysis_*.json under results root", flush=True)
        return 1

    data: Dict[str, dict] = {}
    for arm in arms:
        p = root / f"round_analysis_{arm}.json"
        if not p.exists():
            print(f"missing {p}", flush=True)
            return 1
        data[arm] = json.loads(p.read_text(encoding="utf-8"))

    sizes_all = _discover_sizes(data, arms)
    if not sizes_all:
        print("no summary sizes in round_analysis JSON; nothing to plot", flush=True)
        return 1

    plot_narrative_figures(fig_dir, sizes_all, data)

    print(f"\nAll figures saved to {fig_dir}", flush=True)
    print("Formats: PDF (vector) + PNG (raster, 300 DPI)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
