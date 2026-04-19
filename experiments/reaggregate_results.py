#!/usr/bin/env python3
"""
从 result.json 扫描聚合 (scenario, protocol, size) × seeds 的 mean±std。

用法（将 --root / --out-* 换成你的结果树路径即可）:

  python3 experiments/reaggregate_results.py \\
    --root experiments/results_paper_scalability \\
    --out-json experiments/results_paper_scalability/statistics_summary_reaggregated.json \\
    --out-md experiments/results_paper_scalability/statistics_summary_reaggregated.md

  # 可选：用另一目录中的 PMAP_ACK 结果替换主目录中同名 tag 的 PMAP_ACK
  python3 experiments/reaggregate_results.py \\
    --root experiments/results_paper_scalability \\
    --pmap-ack-replace-root experiments/results_some_other_run \\
    --out-json experiments/results_paper_scalability/statistics_summary_reaggregated.json \\
    --out-md experiments/results_paper_scalability/statistics_summary_reaggregated.md
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


def _scenario_group_from_run_tag(run_tag: str) -> str:
    """统一蜂群目录名 task_random_n10_pmap_s20260417 → task_random_n10_pmap（跨种子聚合）。"""
    m = re.match(r"^(.*)_s(\d{8})$", run_tag)
    return m.group(1) if m else run_tag


def _scenario_from_path(result_path: Path, roots: List[Path]) -> Optional[str]:
    """
    支持两种布局（results_root 为传入的 --root）：
    - 二层：results_root/<run_tag>/result.json → scenario = run_tag 去掉 _s<seed> 后缀
    - 三层：results_root/<scenario_name>/<tag>/result.json → scenario = scenario_name
    """
    try:
        run_dir = result_path.parent
        cand_root = run_dir.parent.resolve()
        for r in roots:
            rr = r.resolve()
            if cand_root == rr:
                return _scenario_group_from_run_tag(run_dir.name)
            inner = run_dir.parent
            if inner.parent.resolve() == rr:
                return inner.name
    except Exception:
        pass
    return None


def _mean_std(vals: List[float]) -> Dict[str, Any]:
    if not vals:
        return {"mean": None, "std": None, "n": 0}
    m = statistics.mean(vals)
    s = statistics.stdev(vals) if len(vals) >= 2 else 0.0
    return {"mean": round(m, 4), "std": round(s, 4), "n": len(vals)}


def collect_runs(
    root: Path,
    *,
    allow_protocols: Optional[Set[str]] = None,
    deny_protocols: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    root = root.resolve()
    runs: List[Dict[str, Any]] = []
    for p in root.rglob("result.json"):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if d.get("status") != "ok":
            continue
        scenario = _scenario_from_path(p, [root])
        if not scenario:
            continue
        prot = str(d.get("protocol", ""))
        if allow_protocols is not None and prot not in allow_protocols:
            continue
        if deny_protocols is not None and prot in deny_protocols:
            continue
        d["_scenario"] = scenario
        d["_result_path"] = str(p)
        runs.append(d)
    return runs


def aggregate_runs(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    by: Dict[Tuple[str, str, int], List[Dict[str, Any]]] = defaultdict(list)
    for r in runs:
        key = (r["_scenario"], str(r.get("protocol", "")), int(r.get("size", 0) or 0))
        by[key].append(r)

    summary: Dict[str, Any] = {}
    scenarios = sorted({k[0] for k in by})
    protocols = sorted({k[1] for k in by})
    sizes = sorted({k[2] for k in by})

    metrics_auth = [
        "protocol_success_rate",
        "success_rate_percent",
        "channel_reliability",
        "timeout",
        "failed",
        "successful",
        "total_sessions",
    ]

    for s in scenarios:
        summary[s] = {}
        for p in protocols:
            summary[s][p] = {}
            for n in sizes:
                group = by.get((s, p, n), [])
                if not group:
                    summary[s][p][str(n)] = None
                    continue
                block: Dict[str, Any] = {}
                for mk in metrics_auth:
                    vals: List[float] = []
                    for r in group:
                        auth = (
                            r.get("analysis", {})
                            .get("analyzer_summary", {})
                            .get("authentication", {})
                        )
                        v = auth.get(mk)
                        if v is None:
                            continue
                        vals.append(float(v))
                    key_out = (
                        "timeout_sessions"
                        if mk == "timeout"
                        else "failed_sessions"
                        if mk == "failed"
                        else "successful_sessions"
                        if mk == "successful"
                        else "total_sessions"
                        if mk == "total_sessions"
                        else mk
                    )
                    block[key_out] = _mean_std(vals)
                summary[s][p][str(n)] = block

    return summary


def aggregate_root(root: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    runs = collect_runs(root)
    return aggregate_runs(runs), runs


def write_markdown(summary: Dict[str, Any], title: str) -> str:
    scenarios = sorted(summary.keys())
    protocols = ["PMAP", "PMAP_ACK", "RLBA_UAV"]
    sizes = [10, 30]
    metric_rows = [
        ("protocol_success_rate", "Protocol success rate (%)"),
        ("success_rate_percent", "Overall success rate (%)"),
        ("channel_reliability", "Channel reliability (%)"),
        ("timeout_sessions", "Timeout sessions (count)"),
        ("failed_sessions", "Explicit failed sessions (count)"),
    ]

    lines = [f"# {title}", "", f"_Generated from `result.json` scans; cells are mean ± std (n seeds)._", ""]

    for mk, mlabel in metric_rows:
        lines.append(f"## {mlabel}")
        lines.append("| Scenario | Protocol | N=10 | N=30 |")
        lines.append("|---|---|---:|---:|")
        for s in scenarios:
            for p in protocols:
                row = []
                for n in sizes:
                    cell = summary.get(s, {}).get(p, {}).get(str(n))
                    if not cell or mk not in cell or not cell[mk]["n"]:
                        row.append("N/A")
                    else:
                        m = cell[mk]["mean"]
                        sd = cell[mk]["std"]
                        nn = cell[mk]["n"]
                        if m is None:
                            row.append("N/A")
                        else:
                            row.append(f"{m:.2f} ± {sd:.2f} (n={nn})")
                lines.append(f"| {s} | {p} | {row[0]} | {row[1]} |")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, required=True, help="results root, e.g. experiments/results_statistical")
    ap.add_argument(
        "--pmap-ack-replace-root",
        type=Path,
        default=None,
        help="If set, PMAP_ACK cells come only from this tree; main --root excludes PMAP_ACK.",
    )
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--out-md", type=Path, required=True)
    ap.add_argument("--title", default="Re-aggregated experiment statistics")
    args = ap.parse_args()

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.parent.mkdir(parents=True, exist_ok=True)

    if args.pmap_ack_replace_root:
        pmap_ack = {"PMAP_ACK"}
        runs_main = collect_runs(args.root.resolve(), deny_protocols=pmap_ack)
        runs_ack = collect_runs(args.pmap_ack_replace_root.resolve(), allow_protocols=pmap_ack)
        runs = runs_main + runs_ack
        summary = aggregate_runs(runs)
        payload: Dict[str, Any] = {
            "source_root": str(args.root.resolve()),
            "pmap_ack_source_root": str(args.pmap_ack_replace_root.resolve()),
            "merge_policy": (
                "PMAP_ACK statistics taken only from pmap_ack_source_root; "
                "all other protocols from source_root (PMAP_ACK under source_root omitted)."
            ),
            "ok_runs": len(runs),
            "ok_runs_by_slice": {
                "source_root_non_pmap_ack": len(runs_main),
                "pmap_ack_source_root": len(runs_ack),
            },
            "summary": summary,
        }
    else:
        summary, runs = aggregate_root(args.root)
        payload = {
            "source_root": str(args.root.resolve()),
            "ok_runs": len(runs),
            "summary": summary,
        }

    args.out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    args.out_md.write_text(write_markdown(summary, args.title), encoding="utf-8")

    print(f"OK runs: {payload['ok_runs']}")
    print(f"Wrote {args.out_json}")
    print(f"Wrote {args.out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
