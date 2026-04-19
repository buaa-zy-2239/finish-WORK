#!/usr/bin/env python3
"""
顺序运行两组边界去同步实验（PMAP vs PMAP_ACK），便于后续绘图对比。

依赖: Ganache + NS-3 与本仓库 simulator_builder.py（路径见 DEFAULT_*）。

用法:
  python3 experiments/run_desync_boundary_suite.py
  NS3_BIN=... SIMULATOR=... python3 experiments/run_desync_boundary_suite.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_BASE = ROOT / "experiments" / "results_desync_boundary"
DEFAULT_NS3 = os.environ.get(
    "NS3_BIN", "/home/zhang/ns/ns-allinone-3.43/ns-3.43/ns3"
)
DEFAULT_SIM = os.environ.get("SIMULATOR", str(ROOT / "simulator_builder.py"))

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from experiments.experiment_presets import build_swarm_argv  # noqa: E402


def _run(profile: str) -> int:
    out = OUT_BASE / profile
    cmd = build_swarm_argv(
        kind="desync_boundary",
        sizes="10,30",
        protocols="PMAP,PMAP_ACK",
        seeds="20260417,20260418,20260419",
        motion_modes="task_random",
        out_root=out,
        academic_profile="twc2025_elevation_aware",
        ns3_bin=DEFAULT_NS3,
        simulator=DEFAULT_SIM,
        between_sleep=2.0,
        boundary_profile=profile,
        loss_pct=None,
    )
    print("[suite]", " ".join(cmd), flush=True)
    return subprocess.call(cmd, cwd=str(ROOT))


def main() -> int:
    OUT_BASE.mkdir(parents=True, exist_ok=True)
    for profile in ("ack_once", "m3m4_once"):
        code = _run(profile)
        if code != 0:
            print(f"[suite] profile={profile} failed code={code}", flush=True)
            return code

    fig_dir = OUT_BASE / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)
    plot = ROOT / "experiments" / "plot_desync_boundary_comparison.py"
    groups = [
        f"ACK边界:{OUT_BASE / 'ack_once'}",
        f"M3/M4边界:{OUT_BASE / 'm3m4_once'}",
    ]
    rc = subprocess.call(
        [
            sys.executable,
            str(plot),
            "--groups",
            *groups,
            "--out",
            str(fig_dir / "pmap_vs_pmap_ack_success.png"),
        ],
        cwd=str(ROOT),
    )
    if rc == 0:
        print(f"[suite] figure -> {fig_dir / 'pmap_vs_pmap_ack_success.png'}", flush=True)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
