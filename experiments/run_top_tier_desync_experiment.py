#!/usr/bin/env python3
"""
顶会取向的边界去同步对比实验：配对 PMAP vs PMAP_ACK、双臂、预注册式协议文档、
轮次分解成功率 + Wilson 区间 + 汇总图。

用法:
  python3 experiments/run_top_tier_desync_experiment.py

环境变量（可选）:
  NS3_BIN, SIMULATOR, MALLOC_ARENA_MAX
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "results_top_tier_desync"
ROUND_ANAL = ROOT / "experiments" / "top_tier_desync" / "round_curve_analysis.py"
PLOT = ROOT / "experiments" / "top_tier_desync" / "plot_top_tier_figures.py"
DEFAULT_NS3 = os.environ.get(
    "NS3_BIN", "/home/zhang/ns/ns-allinone-3.43/ns-3.43/ns3"
)
DEFAULT_SIM = os.environ.get("SIMULATOR", str(ROOT / "simulator_builder.py"))

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from experiments.experiment_presets import build_swarm_argv  # noqa: E402


def _run_swarm(arm: str, profile: str) -> int:
    dest = OUT / arm
    cmd = build_swarm_argv(
        kind="desync_boundary",
        sizes="10,30",
        protocols="PMAP,PMAP_ACK",
        seeds="20260417,20260418,20260419",
        motion_modes="task_random",
        out_root=dest,
        academic_profile="twc2025_elevation_aware",
        ns3_bin=DEFAULT_NS3,
        simulator=DEFAULT_SIM,
        between_sleep=2.0,
        boundary_profile=profile,
        loss_pct=None,
    )
    print("[top_tier]", " ".join(cmd), flush=True)
    return subprocess.call(cmd, cwd=str(ROOT))


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = {
        "protocol_version": "top_tier_desync_1.0",
        "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "design_doc": str(ROOT / "experiments" / "EXPERIMENTS.md"),
        "arms": {
            "ack_once": {"profile": "ack_once", "template": "boundary_ack_once"},
            "m3m4_once": {"profile": "m3m4_once", "template": "boundary_m3m4_once"},
        },
        "ns3": DEFAULT_NS3,
        "simulator": DEFAULT_SIM,
        "runs": [],
    }

    mapping = [("ack_once", "ack_once"), ("m3m4_once", "m3m4_once")]
    for arm, prof in mapping:
        code = _run_swarm(arm, prof)
        manifest["runs"].append({"arm": arm, "exit_code": code, "out": str(OUT / arm)})
        if code != 0:
            (OUT / "MANIFEST.json").write_text(
                json.dumps(manifest, indent=2), encoding="utf-8"
            )
            print(f"[top_tier] swarm failed arm={arm} code={code}", flush=True)
            return code

    # 轮次 + 汇总 JSON
    round_payload: dict = {}
    for arm, _ in mapping:
        dest = OUT / arm
        rj = OUT / f"round_analysis_{arm}.json"
        rc = subprocess.call(
            [sys.executable, str(ROUND_ANAL), "--arm-root", str(dest), "--out-json", str(rj)],
            cwd=str(ROOT),
        )
        if rc != 0:
            return rc
        round_payload[arm] = json.loads(rj.read_text(encoding="utf-8"))

    (OUT / "round_analysis_all_arms.json").write_text(
        json.dumps(round_payload, indent=2), encoding="utf-8"
    )

    # 图
    rc = subprocess.call([sys.executable, str(PLOT), "--results-root", str(OUT)], cwd=str(ROOT))
    if rc != 0:
        print(f"[top_tier] plot exit {rc} (matplotlib 可能未安装)", flush=True)

    manifest["finished_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[top_tier] done -> {OUT}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
