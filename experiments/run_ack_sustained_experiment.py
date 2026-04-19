#!/usr/bin/env python3
"""
持续ACK攻击+恢复实验：多轮拦截后停止，验证PMAP_ACK恢复能力

攻击窗口设计：
- 第10轮开始攻击 (min_completed_sessions=10)
- 第40轮停止攻击 (max_completed_sessions=40)
- 持续30轮攻击，然后观察恢复阶段

用法:
  python3 experiments/run_ack_sustained_experiment.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "results_desync_ack_sustained"
ROUND_ANAL = ROOT / "experiments" / "top_tier_desync" / "round_curve_analysis.py"
PLOT = ROOT / "experiments" / "top_tier_desync" / "plot_top_tier_figures.py"
DEFAULT_NS3 = os.environ.get(
    "NS3_BIN", "/home/zhang/ns/ns-allinone-3.43/ns-3.43/ns3"
)
DEFAULT_SIM = os.environ.get("SIMULATOR", str(ROOT / "simulator_builder.py"))

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from experiments.experiment_presets import build_swarm_argv  # noqa: E402


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    
    manifest = {
        "protocol_version": "ack_sustained_1.0",
        "narrative": "sustained_ack_attack_with_recovery_window",
        "attack_window": {"min_completed": 10, "max_completed": 40, "duration_rounds": 30},
        "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ns3": DEFAULT_NS3,
        "simulator": DEFAULT_SIM,
    }

    # 使用 desync_ack_sustained 预设
    cmd = build_swarm_argv(
        kind="desync_ack_sustained",
        sizes="1",
        protocols="PMAP_ACK",
        seeds="20260417,20260418,20260419",
        motion_modes="task_random",
        out_root=OUT,
        academic_profile="twc2025_elevation_aware",
        ns3_bin=DEFAULT_NS3,
        simulator=DEFAULT_SIM,
        between_sleep=2.0,
        boundary_profile="ack_once",
        loss_pct=None,
        densities=None,
    )
    
    print("[ack_sustained]", " ".join(cmd), flush=True)
    code = subprocess.call(cmd, cwd=str(ROOT))
    
    manifest["swarm_exit_code"] = code
    
    if code != 0:
        (OUT / "MANIFEST.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        print(f"[ack_sustained] swarm failed code={code}", flush=True)
        return code

    # 轮次分析
    rj = OUT / "round_analysis.json"
    rc = subprocess.call(
        [sys.executable, str(ROUND_ANAL), "--arm-root", str(OUT), "--out-json", str(rj)],
        cwd=str(ROOT),
    )
    if rc != 0:
        return rc
    
    round_data = json.loads(rj.read_text(encoding="utf-8"))
    manifest["round_analysis"] = round_data

    # 生成图表
    rc = subprocess.call([sys.executable, str(PLOT), "--results-root", str(OUT)], cwd=str(ROOT))
    if rc != 0:
        print(f"[ack_sustained] plot exit {rc}", flush=True)

    manifest["finished_at_utc"] = time.strftime("Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[ack_sustained] done -> {OUT}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
