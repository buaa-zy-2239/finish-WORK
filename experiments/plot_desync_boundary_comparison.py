#!/usr/bin/env python3
"""
从若干 results 根目录扫描 result.json，汇总 PMAP vs PMAP_ACK 的认证指标并输出对比图。

示例:
  python3 experiments/plot_desync_boundary_comparison.py \\
    --groups "ACK边界:experiments/results_desync_boundary/ack_once" \\
            "M3/M4边界:experiments/results_desync_boundary/m3m4_once" \\
    --out experiments/results_desync_boundary/figures/pmap_vs_pmap_ack.png
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _load_runs(roots: List[Tuple[str, Path]]) -> Dict[str, Dict[str, List[float]]]:
    """
    group_label -> protocol -> list of success_rate_percent (one per result.json)
    """
    out: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    for glabel, root in roots:
        root = root.resolve()
        for p in root.rglob("result.json"):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if d.get("status") != "ok":
                continue
            proto = str(d.get("protocol", "")).upper()
            if proto not in ("PMAP", "PMAP_ACK"):
                continue
            auth = (
                d.get("analysis", {})
                .get("analyzer_summary", {})
                .get("authentication", {})
            )
            v = auth.get("success_rate_percent")
            if v is None:
                continue
            out[glabel][proto].append(float(v))
    return out


def _mean_std(vals: List[float]) -> Tuple[float, float]:
    if not vals:
        return float("nan"), float("nan")
    return statistics.mean(vals), statistics.stdev(vals) if len(vals) > 1 else 0.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--groups",
        nargs="+",
        required=True,
        help='形如 "标签:路径" 的组，可多个',
    )
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    roots: List[Tuple[str, Path]] = []
    for g in args.groups:
        if ":" not in g:
            raise SystemExit(f"bad --groups entry (need label:path): {g}")
        label, path = g.split(":", 1)
        roots.append((label.strip(), Path(path.strip())))

    data = _load_runs(roots)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib 未安装，改为写出 CSV", flush=True)
        lines = ["group,protocol,mean_success_pct,std,n"]
        for glabel in sorted(data.keys()):
            for proto in ("PMAP", "PMAP_ACK"):
                vals = data[glabel].get(proto, [])
                m, s = _mean_std(vals)
                lines.append(f"{glabel},{proto},{m:.4f},{s:.4f},{len(vals)}")
        args.out.with_suffix(".csv").write_text("\n".join(lines), encoding="utf-8")
        print(f"Wrote {args.out.with_suffix('.csv')}")
        return 0

    labels = list(data.keys())
    x = range(len(labels))
    width = 0.35
    pmap_means = []
    pmap_stds = []
    ack_means = []
    ack_stds = []
    for gl in labels:
        pm = data[gl].get("PMAP", [])
        pa = data[gl].get("PMAP_ACK", [])
        m1, s1 = _mean_std(pm)
        m2, s2 = _mean_std(pa)
        pmap_means.append(m1)
        pmap_stds.append(s1)
        ack_means.append(m2)
        ack_stds.append(s2)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar([i - width / 2 for i in x], pmap_means, width, yerr=pmap_stds, label="PMAP", capsize=4)
    ax.bar([i + width / 2 for i in x], ack_means, width, yerr=ack_stds, label="PMAP_ACK", capsize=4)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=12, ha="right")
    ax.set_ylabel("Overall D2Z success rate (%)")
    ax.set_title("Boundary desync (limited interference + multi-round reauth)")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(args.out, dpi=150)
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
