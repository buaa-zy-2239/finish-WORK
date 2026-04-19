#!/usr/bin/env python3
"""
标准化论文实验入口：按「实验类型 + 规模 + 协议」生成或直接执行 swarm / 顶会流水线。

示例:
  python3 experiments/run_paper_experiment.py --list-kinds
  python3 experiments/run_paper_experiment.py --kind baseline --sizes 10 --protocols PMAP_ACK --dry-run
  python3 experiments/run_paper_experiment.py --kind desync_boundary --sizes 10,30 \\
      --protocols PMAP,PMAP_ACK --boundary-profile ack_once \\
      --out-root experiments/results_desync_boundary/ack_once
  python3 experiments/run_paper_experiment.py --kind top_tier

环境变量: NS3_BIN, SIMULATOR（与 swarm 一致）。逐步复现见 `experiments/EXPERIMENTS.md` 第 0 节。
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.experiment_presets import (  # noqa: E402
    KINDS,
    build_swarm_argv,
    default_ns3_bin,
    default_simulator,
    list_kind_titles,
)


def _run_top_tier_pipeline(ns3: str, sim: str) -> int:
    top = ROOT / "experiments" / "run_top_tier_desync_experiment.py"
    env = os.environ.copy()
    env["NS3_BIN"] = ns3
    env["SIMULATOR"] = sim
    return subprocess.call([sys.executable, str(top)], cwd=str(ROOT), env=env)


def main() -> int:
    ap = argparse.ArgumentParser(description="Paper-oriented experiment runner (preset → swarm)")
    ap.add_argument(
        "--kind",
        choices=sorted(KINDS.keys()),
        required=False,
        help="实验类型；与 experiment_presets.KINDS 一致",
    )
    ap.add_argument("--sizes", default="", help="逗号分隔规模，默认随 kind")
    ap.add_argument("--protocols", default="", help="逗号分隔协议，默认随 kind")
    ap.add_argument("--seeds", default="", help="逗号分隔种子，默认随 kind")
    ap.add_argument("--motion-modes", default="", help="默认 task_random")
    ap.add_argument(
        "--out-root",
        type=Path,
        default=None,
        help="结果根目录；默认使用预设中的 default_out_root（相对仓库根）",
    )
    ap.add_argument(
        "--boundary-profile",
        choices=("ack_once", "m3m4_once"),
        default=None,
        help="仅 kind=desync_boundary 时覆盖 boundary_ack / boundary_m3m4",
    )
    ap.add_argument(
        "--loss-pct",
        type=float,
        default=None,
        help="均匀上下行丢包率 [0,1]；覆盖预设中的 uplink/downlink",
    )
    ap.add_argument(
        "--academic-profile",
        default="",
        help="覆盖预设默认 academic profile",
    )
    ap.add_argument(
        "--densities",
        default="",
        help="密度级别: low(1), medium(10), high(50) UAVs/km²，用于scalability实验",
    )
    ap.add_argument("--ns3", default=default_ns3_bin())
    ap.add_argument("--simulator", default=default_simulator())
    ap.add_argument(
        "--between-sleep",
        type=float,
        default=None,
        help="两次 NS3 运行之间休眠秒数；默认随 kind",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="只打印将要执行的命令，不运行",
    )
    ap.add_argument(
        "--list-kinds",
        action="store_true",
        help="列出内置实验类型及说明",
    )
    args = ap.parse_args()

    if args.list_kinds:
        for k, title in sorted(list_kind_titles().items()):
            note = KINDS[k].notes
            extra = f" | {note}" if note else ""
            print(f"{k}: {title}{extra}", flush=True)
        return 0

    if not args.kind:
        ap.error("必须指定 --kind 或使用 --list-kinds")

    if args.kind == "top_tier":
        if args.dry_run:
            print(
                "[dry-run] would run:",
                sys.executable,
                str(ROOT / "experiments" / "run_top_tier_desync_experiment.py"),
                flush=True,
            )
            return 0
        return _run_top_tier_pipeline(args.ns3, args.simulator)

    sm = KINDS[args.kind].swarm
    sizes = args.sizes.strip() or sm.default_sizes
    protocols = args.protocols.strip() or sm.default_protocols
    seeds = args.seeds.strip() or sm.default_seeds
    motion = args.motion_modes.strip() or sm.default_motion_modes
    if args.out_root is None:
        out_root = (ROOT / sm.default_out_root.strip("/\\")).resolve()
    else:
        out_root = args.out_root
        out_root = out_root if out_root.is_absolute() else (ROOT / out_root)
        out_root = out_root.resolve()

    academic = args.academic_profile.strip() or sm.default_academic_profile

    cmd = build_swarm_argv(
        kind=args.kind,
        sizes=sizes,
        protocols=protocols,
        seeds=seeds,
        motion_modes=motion,
        out_root=out_root,
        academic_profile=academic,
        ns3_bin=args.ns3,
        simulator=args.simulator,
        between_sleep=args.between_sleep,
        boundary_profile=args.boundary_profile,
        loss_pct=args.loss_pct,
        densities=args.densities,
    )

    print("[paper_exp]", " ".join(cmd), flush=True)
    if args.dry_run:
        return 0
    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
