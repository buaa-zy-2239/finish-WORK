#!/usr/bin/env python3
"""
从已有仿真 logs/ 重新解析并写回各 run 目录下的 result.json 中的 analysis 字段，
与 swarm_unified_scenario_experiment._analyze_log_dir 口径一致（随 Backend 解析器更新而更新）。

用法:
  python3 experiments/reanalyze_swarm_result_json.py \\
    --results-root experiments/results_desync_microscopic/ack_once
  python3 experiments/reanalyze_swarm_result_json.py \\
    --results-root experiments/results_desync_microscopic
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.swarm_unified_scenario_experiment import _analyze_log_dir  # noqa: E402


def _iter_result_files(results_root: Path) -> list[Path]:
    return sorted(results_root.rglob("result.json"))


def main() -> int:
    ap = argparse.ArgumentParser(description="Re-parse logs and refresh result.json analysis")
    ap.add_argument(
        "--results-root",
        type=Path,
        required=True,
        help="扫描该目录下所有 result.json（递归）",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="只打印将更新的路径，不写文件",
    )
    args = ap.parse_args()
    root: Path = args.results_root
    if not root.is_dir():
        print(f"[reanalyze] not a directory: {root}", file=sys.stderr)
        return 1

    updated = 0
    skipped = 0
    errors = 0
    for rp in _iter_result_files(root):
        try:
            data = json.loads(rp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"[reanalyze] skip read error {rp}: {e}", file=sys.stderr)
            errors += 1
            continue
        if data.get("status") != "ok":
            skipped += 1
            continue
        log_dir = data.get("log_dir")
        if not log_dir or not Path(log_dir).is_dir():
            print(f"[reanalyze] skip missing logs {rp}", file=sys.stderr)
            skipped += 1
            continue
        try:
            analysis = _analyze_log_dir(str(Path(log_dir).resolve()))
        except Exception as e:
            print(f"[reanalyze] analyze failed {rp}: {e}", file=sys.stderr)
            errors += 1
            continue
        if args.dry_run:
            print(f"[dry-run] would update {rp}")
            updated += 1
            continue
        data["analysis"] = analysis
        rp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        print(f"[reanalyze] updated {rp}", flush=True)
        updated += 1

    print(
        json.dumps(
            {"updated": updated, "skipped": skipped, "errors": errors, "root": str(root)},
            indent=2,
        )
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
