#!/usr/bin/env python3
"""
扫描某次研究输出根目录下各子目录的 result.json，按 (motion, N, ρ, protocol, gm_stress) 聚合跨种子指标，
输出 JSON 摘要并生成带误差棒的规模曲线（按密度分层）。
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
# `analysis` 位于 experiments/analysis（非顶层包名）
if str(ROOT / "experiments") not in sys.path:
    sys.path.insert(0, str(ROOT / "experiments"))

from analysis.statistical_utils import StatisticalAnalyzer  # noqa: E402

try:
    from analysis.chart_generator import TopTierChartGenerator  # noqa: E402
except Exception:  # pragma: no cover
    TopTierChartGenerator = None  # type: ignore


def _parse_tag(tag: str) -> Optional[Dict[str, Any]]:
    """解析 swarm 生成的 tag（可含 _gm* 与 _ch* 信道应力后缀）。"""
    m = re.match(
        r"^(?P<motion>[\w_]+)_n(?P<n>\d+)_d(?P<rho>\d+)_(?P<proto>pmap_ack|pmap)_s(?P<seed>\d+)",
        tag.strip(),
        re.IGNORECASE,
    )
    if not m:
        return None
    rest = tag.strip()[m.end() :]
    gm = "nominal"
    if rest.startswith("_gm"):
        for tier in ("conservative", "aggressive", "nominal"):
            suf = f"_gm{tier}"
            if rest.startswith(suf):
                gm = tier
                rest = rest[len(suf) :]
                break
    ch = ""
    if rest.startswith("_ch"):
        ch = rest
    return {
        "motion": m.group("motion"),
        "n": int(m.group("n")),
        "rho": int(m.group("rho")),
        "proto": m.group("proto").upper().replace("PMAP_ACK", "PMAP_ACK"),
        "seed": int(m.group("seed")),
        "gm_stress": gm,
        "channel_suffix": ch or "",
    }


def _nested_float(d: Dict[str, Any], *keys: str) -> Optional[float]:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    if isinstance(cur, (int, float)) and not (isinstance(cur, float) and math.isnan(cur)):
        return float(cur)
    return None


def _ci_summary(values: List[float]) -> Dict[str, Any]:
    clean = [float(v) for v in values if v is not None and not (isinstance(v, float) and math.isnan(v))]
    if not clean:
        return {"mean": float("nan"), "ci_95_margin": float("nan"), "n_samples": 0}
    if len(clean) == 1:
        v = clean[0]
        return {"mean": v, "ci_95_margin": 0.0, "n_samples": 1}
    s = StatisticalAnalyzer.calculate_summary(clean)
    if math.isnan(s.mean):
        return {"mean": float("nan"), "ci_95_margin": float("nan"), "n_samples": len(clean)}
    return {"mean": s.mean, "ci_95_margin": s.ci_95_margin, "n_samples": s.n_samples}


def load_runs(results_root: Path) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    out: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for p in sorted(results_root.glob("*/result.json")):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        tag = rec.get("tag") or p.parent.name
        meta = _parse_tag(str(tag))
        if not meta:
            continue
        if rec.get("status") != "ok":
            continue
        out.append((meta, rec))
    return out


def _aggregate_errors(error_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """聚合错误数据"""
    if not error_list:
        return {"total": 0, "M1_errors": 0, "M2_errors": 0, "M3_M4_errors": 0}
    total = sum(e.get("total", 0) for e in error_list)
    m1 = sum(e.get("M1_errors", 0) for e in error_list)
    m2 = sum(e.get("M2_errors", 0) for e in error_list)
    m3_m4 = sum(e.get("M3_M4_errors", 0) for e in error_list)
    return {"total": total, "M1_errors": m1, "M2_errors": m2, "M3_M4_errors": m3_m4}


def _aggregate_distance_impact(distance_list: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """聚合距离影响数据"""
    if not distance_list:
        return []
    # 合并所有距离区间数据
    merged = defaultdict(lambda: {"total_sessions": 0, "successful_sessions": 0})
    for session_list in distance_list:
        for item in session_list:
            bucket = item.get("bucket")
            if bucket:
                merged[bucket]["total_sessions"] += item.get("total_sessions", 0)
                merged[bucket]["successful_sessions"] += item.get("successful_sessions", 0)
    # 计算成功率
    result = []
    for bucket, data in sorted(merged.items()):
        total = data["total_sessions"]
        successful = data["successful_sessions"]
        success_rate = (successful / total * 100) if total > 0 else 0
        result.append({
            "bucket": bucket,
            "total_sessions": total,
            "successful_sessions": successful,
            "success_rate_percent": success_rate
        })
    return result


def _aggregate_recovery(recovery_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """聚合恢复性能数据"""
    if not recovery_list:
        return {"recovery_completion_ratio": 0.0, "retry_successes": 0}
    ratio = sum(r.get("recovery_completion_ratio", 0.0) for r in recovery_list) / len(recovery_list)
    retry_successes = sum(r.get("reauthentication_cost", {}).get("retry_successes", 0) for r in recovery_list)
    return {"recovery_completion_ratio": ratio, "retry_successes": retry_successes}


def aggregate(
    runs: List[Tuple[Dict[str, Any], Dict[str, Any]]],
    filter_density: Optional[int] = None,
    filter_gm: Optional[str] = None,
) -> Dict[str, Any]:
    # key -> list of success_rate_percent
    by_cell: DefaultDict[str, List[float]] = defaultdict(list)
    by_cell_duration: DefaultDict[str, List[float]] = defaultdict(list)
    by_cell_errors: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
    by_cell_distance: DefaultDict[str, List[List[Dict[str, Any]]]] = defaultdict(list)
    by_cell_recovery: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
    by_cell_timeout: DefaultDict[str, List[int]] = defaultdict(list)
    by_cell_key_mismatch: DefaultDict[str, List[int]] = defaultdict(list)
    cell_meta: Dict[str, Dict[str, Any]] = {}

    for meta, rec in runs:
        if filter_density is not None and meta["rho"] != filter_density:
            continue
        if filter_gm and meta["gm_stress"] != filter_gm.lower():
            continue
        auth = (rec.get("analysis") or {}).get("analyzer_summary", {}).get("authentication") or {}
        sr = auth.get("success_rate_percent")
        if sr is None:
            continue
        ch_key = meta.get("channel_suffix") or "none"
        key = (
            f"{meta['motion']}|n={meta['n']}|rho={meta['rho']}|{meta['proto']}"
            f"|gm={meta['gm_stress']}|ch={ch_key}"
        )
        by_cell[key].append(float(sr))
        cell_meta[key] = meta
        
        # 聚合延迟数据
        dur = _nested_float(rec, "analysis", "analyzer_summary", "timing", "avg_duration_seconds")
        if dur is not None:
            by_cell_duration[key].append(dur)
        
        # 聚合错误数据
        errors = (rec.get("analysis") or {}).get("analyzer_summary", {}).get("errors") or {}
        if errors:
            by_cell_errors[key].append(errors)
        
        # 聚合距离影响数据
        success_vs_distance = (rec.get("analysis") or {}).get("analyzer_summary", {}).get("mechanism", {}).get("success_vs_distance")
        if success_vs_distance:
            by_cell_distance[key].append(success_vs_distance)
        
        # 聚合恢复性能数据
        mechanism = (rec.get("analysis") or {}).get("analyzer_summary", {}).get("mechanism") or {}
        if mechanism:
            by_cell_recovery[key].append(mechanism)
        
        # 聚合超时和密钥不匹配数据
        by_cell_timeout[key].append(auth.get("timeout", 0))
        by_cell_key_mismatch[key].append(auth.get("key_mismatch_sessions", 0))

    summaries: Dict[str, Any] = {}
    for key, vals in by_cell.items():
        summaries[key] = {
            "meta": cell_meta[key],
            "success_rate_percent": _ci_summary(vals),
            "avg_duration_seconds": _ci_summary(by_cell_duration.get(key, [])),
            "errors": _aggregate_errors(by_cell_errors.get(key, [])),
            "distance_impact": _aggregate_distance_impact(by_cell_distance.get(key, [])),
            "recovery": _aggregate_recovery(by_cell_recovery.get(key, [])),
            "timeout_sessions": sum(by_cell_timeout.get(key, [])),
            "key_mismatch_sessions": sum(by_cell_key_mismatch.get(key, [])),
        }

    return {"cells": summaries, "n_raw_runs": len(runs)}


def build_chart_payload_for_metric(
    summaries: Dict[str, Any],
    motion: str,
    rho: int,
    gm_stress: str,
    metric_block: str,
) -> Dict[str, Dict[int, Dict[str, Any]]]:
    """TopTierChartGenerator.plot_scalability_curve 所需结构；metric_block 为 aggregate 写入的键。"""
    data: Dict[str, Dict[int, Dict[str, Any]]] = defaultdict(dict)
    prefix = f"{motion}|"
    mid = f"|rho={rho}|"
    suffix = f"|gm={gm_stress}|"
    for key, block in summaries["cells"].items():
        if not key.startswith(prefix) or mid not in key or suffix not in key:
            continue
        meta = block["meta"]
        proto = meta["proto"]
        n = meta["n"]
        s = block.get(metric_block) or {}
        mean = s.get("mean")
        margin = s.get("ci_95_margin")
        if mean is None or margin is None or (isinstance(mean, float) and math.isnan(mean)):
            continue
        data[proto][n] = {"mean": float(mean), "ci_95_margin": float(margin)}
    return dict(data)


def build_chart_payload_for_errors(
    summaries: Dict[str, Any],
    motion: str,
    rho: int,
    gm_stress: str,
) -> Dict[str, Dict[str, int]]:
    """TopTierChartGenerator.plot_error_distribution 所需结构"""
    data: Dict[str, Dict[str, int]] = defaultdict(dict)
    prefix = f"{motion}|"
    mid = f"|rho={rho}|"
    suffix = f"|gm={gm_stress}|"
    for key, block in summaries["cells"].items():
        if not key.startswith(prefix) or mid not in key or suffix not in key:
            continue
        meta = block["meta"]
        proto = meta["proto"]
        errors = block.get("errors", {})
        timeout = block.get("timeout_sessions", 0)
        key_mismatch = block.get("key_mismatch_sessions", 0)
        
        error_data = {
            "Timeout": timeout,
            "Key Mismatch": key_mismatch,
            "M1 Errors": errors.get("M1_errors", 0),
            "M2 Errors": errors.get("M2_errors", 0),
            "M3/M4 Errors": errors.get("M3_M4_errors", 0)
        }
        data[proto] = error_data
    return dict(data)


def build_chart_payload_for_distance(
    summaries: Dict[str, Any],
    motion: str,
    rho: int,
    gm_stress: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """TopTierChartGenerator.plot_distance_impact 所需结构"""
    data: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    prefix = f"{motion}|"
    mid = f"|rho={rho}|"
    suffix = f"|gm={gm_stress}|"
    for key, block in summaries["cells"].items():
        if not key.startswith(prefix) or mid not in key or suffix not in key:
            continue
        meta = block["meta"]
        proto = meta["proto"]
        distance_impact = block.get("distance_impact", [])
        if distance_impact:
            data[proto] = distance_impact
    return dict(data)


def main() -> int:
    ap = argparse.ArgumentParser(description="Aggregate scalability-style results and plot curves.")
    ap.add_argument("--results-root", type=Path, required=True, help="e.g. experiments/results_repro_s01")
    ap.add_argument("--charts-dir", type=Path, default=None, help="default: <results-root>/charts")
    ap.add_argument("--filter-density", type=int, default=None, help="only this rho (integer as in tag, e.g. 1)")
    ap.add_argument("--filter-gm", type=str, default=None, help="conservative|nominal|aggressive")
    args = ap.parse_args()

    root: Path = args.results_root.resolve()
    if not root.is_dir():
        print(f"[err] not a directory: {root}", file=sys.stderr)
        return 2

    runs = load_runs(root)
    blob = aggregate(runs, filter_density=args.filter_density, filter_gm=args.filter_gm)
    out_json = root / "aggregated_statistics.json"
    out_json.write_text(json.dumps(blob, indent=2), encoding="utf-8")
    print(f"[ok] wrote {out_json} ({len(blob['cells'])} cells)")

    charts_dir = (args.charts_dir or (root / "charts")).resolve()
    charts_dir.mkdir(parents=True, exist_ok=True)

    if TopTierChartGenerator is None:
        print("[warn] chart_generator not available, skip figures")
        return 0

    motions = sorted({m["motion"] for m, _ in runs})
    rhos = sorted({m["rho"] for m, _ in runs})
    gm_list = sorted({m["gm_stress"] for m, _ in runs})

    gen = TopTierChartGenerator(str(charts_dir))
    for motion in motions:
        for rho in rhos:
            for gm in gm_list:
                base = f"scalability_{motion}_rho{rho}_gm{gm}"
                # 生成可扩展性曲线
                payload_sr = build_chart_payload_for_metric(
                    blob, motion, rho, gm, "success_rate_percent"
                )
                if len(payload_sr) >= 1 and not all(len(v) < 1 for v in payload_sr.values()):
                    gen.plot_scalability_curve(
                        payload_sr,
                        metric="success_rate_percent",
                        ylabel="Session completion rate (%)",
                        title=f"{motion} (ρ={rho} UAV/km², GM={gm})",
                        filename=base,
                    )
                    print(f"[ok] chart {base}.pdf")

                payload_dur = build_chart_payload_for_metric(
                    blob, motion, rho, gm, "avg_duration_seconds"
                )
                if len(payload_dur) >= 1 and not all(len(v) < 1 for v in payload_dur.values()):
                    gen.plot_scalability_curve(
                        payload_dur,
                        metric="avg_duration_seconds",
                        ylabel="Avg. session duration (s)",
                        title=f"{motion} (ρ={rho} UAV/km², GM={gm}) — latency",
                        filename=f"{base}_avg_duration",
                    )
                    print(f"[ok] chart {base}_avg_duration.pdf")
                
                # 生成错误分布图表
                payload_errors = build_chart_payload_for_errors(
                    blob, motion, rho, gm
                )
                if payload_errors:
                    gen.plot_error_distribution(
                        payload_errors,
                        title=f"Error Distribution ({motion}, ρ={rho} UAV/km², GM={gm})",
                        filename=f"error_distribution_{motion}_rho{rho}_gm{gm}"
                    )
                    print(f"[ok] chart error_distribution_{motion}_rho{rho}_gm{gm}.pdf")
                
                # 生成距离影响图表
                payload_distance = build_chart_payload_for_distance(
                    blob, motion, rho, gm
                )
                if payload_distance:
                    gen.plot_distance_impact(
                        payload_distance,
                        title=f"Distance Impact ({motion}, ρ={rho} UAV/km², GM={gm})",
                        filename=f"distance_impact_{motion}_rho{rho}_gm{gm}"
                    )
                    print(f"[ok] chart distance_impact_{motion}_rho{rho}_gm{gm}.pdf")
                
                # 生成综合仪表盘
                gen.plot_multi_metric_dashboard(
                    blob,
                    motion=motion,
                    rho=rho,
                    gm_stress=gm,
                    title=f"Scalability Dashboard ({motion}, ρ={rho} UAV/km², GM={gm})",
                    filename=f"dashboard_{motion}_rho{rho}_gm{gm}"
                )
                print(f"[ok] chart dashboard_{motion}_rho{rho}_gm{gm}.pdf")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
