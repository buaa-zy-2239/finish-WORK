#!/usr/bin/env python3
"""
按「每 UAV 第 r 次闭合的 D2Z 会话」聚合瞬时成功率（配对实验的轮次曲线）。

依赖 Backend 的 D2ZLogParser / D2ZAnalyzer（与 result.json 同源事件模型）。
"""

from __future__ import annotations

import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[2]

_PROTO_ORDER = ("PMAP", "PMAP_ACK", "RLBA_UAV")


def _proto_sort_key(p: str) -> int:
    try:
        return _PROTO_ORDER.index(p.upper())
    except ValueError:
        return len(_PROTO_ORDER)


def _read_scenario_desync_from_arm(arm_root: Path) -> Dict[str, Any]:
    """从任意一次成功的 run 的 inputs/config.json 读取场景级去同步参数（用于图注 / 攻击窗）。"""
    for result_path in sorted(arm_root.glob("task_random_n*/result.json")):
        try:
            d = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if d.get("status") != "ok":
            continue
        cfgp = d.get("config_path")
        if not cfgp:
            continue
        cp = Path(str(cfgp))
        if not cp.is_file():
            continue
        try:
            cj = json.loads(cp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        sc = cj.get("scenario") or {}
        sec = (cj.get("security_profile") or {}).get("attack_model") or {}
        return {
            "desync_template": sc.get("desync_template") or sec.get("desync_template"),
            "desync_attack_min_completed_sessions": sc.get("desync_attack_min_completed_sessions"),
            "desync_attack_max_completed_sessions": sc.get("desync_attack_max_completed_sessions"),
            "reauth_rounds": sc.get("reauth_rounds"),
        }
    return {}


def _wilson_ci(successes: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n <= 0:
        return float("nan"), float("nan")
    phat = successes / n
    denom = 1 + z**2 / n
    center = (phat + z**2 / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(phat * (1 - phat) / n + z**2 / (4 * n**2))
    return max(0.0, (center - margin) * 100), min(1.0, (center + margin) * 100)


def analyze_log_dir_rounds(log_dir: str) -> Dict[str, Any]:
    sys.path.insert(0, str(ROOT / "Backend"))
    from analysis.protocol_analyzer import D2ZAnalyzer  # noqa: E402
    from core.log_parser import D2ZLogParser  # noqa: E402
    from core.event_models import D2ZEvent  # noqa: E402

    events = D2ZLogParser.parse_all_logs(log_dir)
    an = D2ZAnalyzer(events)
    
    # 检测攻击事件（去同步攻击发生的 sim_time）
    attack_times: List[float] = []
    for e in events:
        step = (e.protocol_step or "").upper()
        # 检测各种攻击标记
        if any(x in step for x in ["D2Z_ACK_SUPPRESSED", "M3_M4_INTERCEPTED", "ATTACK"]):
            attack_times.append(e.sim_time)
    
    by_uav: Dict[int, list] = defaultdict(list)
    for s in an.sessions.values():
        by_uav[s.uav_id].append(s)
    for uid in by_uav:
        by_uav[uid].sort(key=lambda x: x.start_time)

    max_r = max((len(v) for v in by_uav.values()), default=0)
    if max_r == 0:
        return {"max_rounds": 0, "rounds": [], "attack_rounds": [], "cumulative": []}
    
    # 确定攻击发生的轮次（基于时间匹配）
    attack_rounds: set[int] = set()
    for at in attack_times:
        for uid, lst in by_uav.items():
            for i, sess in enumerate(lst):
                # 攻击时间落在该会话时间窗口内
                if sess.start_time <= at <= (sess.end_time or (sess.start_time + 10)):
                    attack_rounds.add(i + 1)  # 1-based
                    break
    
    # 轮次成功率（瞬时）
    per_round_success: List[List[float]] = [[] for _ in range(max_r)]
    for uid, lst in by_uav.items():
        for i, sess in enumerate(lst):
            per_round_success[i].append(1.0 if sess.success else 0.0)

    rounds_out = []
    cumulative_successes: List[int] = []  # 累积成功次数
    cum_sum = 0
    for i in range(max_r):
        vals = per_round_success[i]
        n = len(vals)
        succ = int(sum(vals))
        cum_sum += succ
        cumulative_successes.append(cum_sum)
        mean_pct = 100.0 * statistics.mean(vals) if n else float("nan")
        lo, hi = _wilson_ci(succ, n)
        rounds_out.append(
            {
                "round": i + 1,
                "n_samples": n,
                "successes": succ,
                "mean_success_pct": round(mean_pct, 4),
                "wilson95_low_pct": round(lo, 4),
                "wilson95_high_pct": round(hi, 4),
                "cumulative_successes": cum_sum,  # 新增：累积成功数
                "is_attack_round": (i + 1) in attack_rounds,  # 新增：是否攻击轮次
            }
        )
    
    return {
        "max_rounds": max_r, 
        "rounds": rounds_out, 
        "attack_rounds": sorted(attack_rounds),
        "cumulative": cumulative_successes,
    }


def aggregate_arm_results(arm_root: Path) -> Dict[str, Any]:
    """arm_root 下每个 task_random_n*_* 目录一次 run。"""
    arm_root = arm_root.resolve()
    by_key: Dict[Tuple[int, str, int], List[Dict[str, Any]]] = defaultdict(list)
    for result_path in sorted(arm_root.glob("task_random_n*/result.json")):
        try:
            d = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if d.get("status") != "ok":
            continue
        tag = result_path.parent.name
        size = int(d.get("size", 0))
        proto = str(d.get("protocol", "")).upper()
        seed = int(d.get("seed", 0))
        log_dir = d.get("log_dir") or str(result_path.parent / "logs")
        rd = analyze_log_dir_rounds(log_dir)
        auth = (
            d.get("analysis", {})
            .get("analyzer_summary", {})
            .get("authentication", {})
        )
        by_key[(size, proto, seed)].append(
            {
                "tag": tag,
                "rounds": rd["rounds"],
                "auth": auth,
            }
        )

    protos_all = sorted({k[1] for k in by_key}, key=_proto_sort_key)
    scenario_meta = _read_scenario_desync_from_arm(arm_root)

    # 每个 (size, proto) 跨种子合并轮次 Wilson（把各 run 同轮样本合并）
    summary: Dict[str, Any] = {}
    sizes_present = sorted({k[0] for k in by_key})
    if not sizes_present:
        return {
            "arm_root": str(arm_root),
            "by_run_detail_keys": len(by_key),
            "meta": {"scenario_desync": scenario_meta, "protocols_aggregated": protos_all},
            "attack_round_span_by_size": {},
            "summary": {},
        }

    for size in sizes_present:
        protos_for_size = sorted(
            {k[1] for k in by_key if k[0] == size},
            key=_proto_sort_key,
        )
        for proto in protos_for_size:
            merged_rounds: Dict[int, List[float]] = defaultdict(list)
            merged_attack_flags: Dict[int, List[bool]] = defaultdict(list)
            end_metrics: List[Dict[str, float]] = []

            for seed in sorted({k[2] for k in by_key if k[0] == size and k[1] == proto}):
                runs = by_key.get((size, proto, seed), [])
                if not runs:
                    continue
                r0 = runs[0]
                end_metrics.append(
                    {
                        "success_rate_percent": float(
                            r0["auth"].get("success_rate_percent", 0) or 0
                        ),
                        "protocol_success_rate": float(
                            r0["auth"].get("protocol_success_rate", 0) or 0
                        ),
                        "timeout_sessions": float(r0["auth"].get("timeout", 0) or 0),
                    }
                )
                for row in r0["rounds"]:
                    rid = row["round"]
                    succ = row["successes"]
                    n = row["n_samples"]
                    merged_rounds[rid].extend([1.0] * succ + [0.0] * (n - succ))
                    is_attack = row.get("is_attack_round", False)
                    merged_attack_flags[rid].append(is_attack)

            rounds_agg = []
            cum_sum = 0
            for rid in sorted(merged_rounds.keys()):
                bits = merged_rounds[rid]
                n = len(bits)
                succ = int(sum(bits))
                cum_sum += succ
                mean_pct = 100.0 * statistics.mean(bits) if n else float("nan")
                lo, hi = _wilson_ci(succ, n)
                is_attack_any = any(merged_attack_flags.get(rid, [False]))
                rounds_agg.append(
                    {
                        "round": rid,
                        "n_samples": n,
                        "successes": succ,
                        "mean_success_pct": round(mean_pct, 4),
                        "wilson95_low_pct": round(lo, 4),
                        "wilson95_high_pct": round(hi, 4),
                        "cumulative_successes": cum_sum,
                        "is_attack_round": is_attack_any,
                    }
                )

            def mean_std(key: str):
                xs = [m[key] for m in end_metrics]
                if not xs:
                    return None
                m = statistics.mean(xs)
                s = statistics.stdev(xs) if len(xs) > 1 else 0.0
                return {"mean": round(m, 4), "std": round(s, 4), "n": len(xs)}

            summary[f"n{size}_{proto.lower()}"] = {
                "end_of_sim": {
                    "success_rate_percent": mean_std("success_rate_percent"),
                    "protocol_success_rate": mean_std("protocol_success_rate"),
                    "timeout_sessions": mean_std("timeout_sessions"),
                },
                "rounds_pooled_across_seeds": rounds_agg,
            }

    attack_round_span_by_size: Dict[str, List[int]] = {}
    for size in sizes_present:
        rids: set[int] = set()
        for key, block in summary.items():
            if not key.startswith(f"n{size}_"):
                continue
            for row in block.get("rounds_pooled_across_seeds") or []:
                if row.get("is_attack_round"):
                    rids.add(int(row["round"]))
        if rids:
            attack_round_span_by_size[str(size)] = [min(rids), max(rids)]

    return {
        "arm_root": str(arm_root),
        "by_run_detail_keys": len(by_key),
        "meta": {"scenario_desync": scenario_meta, "protocols_aggregated": protos_all},
        "attack_round_span_by_size": attack_round_span_by_size,
        "summary": summary,
    }


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--arm-root", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    args = ap.parse_args()
    payload = aggregate_arm_results(args.arm_root)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote {args.out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
