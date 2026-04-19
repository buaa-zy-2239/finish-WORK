#!/usr/bin/env python3
"""
微观叙事：单机 (N=1) 与 ZSP 多轮认证 + 边界去同步三臂（持续 ACK / 单轮 M3M4 / 持续 M3M4），
轮次分析与图与 top_tier 流水线一致，输出独立目录便于正文「案例」引用。

调度轮次默认见 experiment_presets.desync_boundary_micro（当前 reauth_rounds=120）。

用法:
  python3 experiments/run_microscopic_desync_experiment.py

环境变量: NS3_BIN, SIMULATOR（与 swarm 一致）。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "results_desync_microscopic"
ROUND_ANAL = ROOT / "experiments" / "top_tier_desync" / "round_curve_analysis.py"
PLOT = ROOT / "experiments" / "top_tier_desync" / "plot_top_tier_figures.py"
DEFAULT_NS3 = os.environ.get(
    "NS3_BIN", "/home/zhang/ns/ns-allinone-3.43/ns-3.43/ns3"
)
DEFAULT_SIM = os.environ.get("SIMULATOR", str(ROOT / "simulator_builder.py"))

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from experiments.experiment_presets import build_swarm_argv  # noqa: E402


def _run_swarm(arm: str, kind: str, protocols: str, profile: str) -> int:
    dest = OUT / arm
    cmd = build_swarm_argv(
        kind=kind,
        sizes="1",
        protocols=protocols,
        seeds="20260417,20260418,20260419",
        motion_modes="task_random",
        out_root=dest,
        academic_profile="twc2025_elevation_aware",
        ns3_bin=DEFAULT_NS3,
        simulator=DEFAULT_SIM,
        between_sleep=2.0,
        boundary_profile=profile,
        loss_pct=None,
        densities=None,
    )
    print("[micro_desync]", " ".join(cmd), flush=True)
    return subprocess.call(cmd, cwd=str(ROOT))


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = {
        "protocol_version": "desync_microscopic_1.3",
        "narrative": "single_UAV_ZSP_multi_round_scheduled_D2Z_mid_stream_boundary_attack_default_120_rounds",
        "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "design_doc": str(ROOT / "experiments" / "EXPERIMENTS.md"),
        "arms": {
            "ack_once": {"profile": "ack_once", "template": "boundary_ack_once", "attack_rounds": "10轮持续"},
            "m3m4_once": {"profile": "m3m4_once", "template": "boundary_m3m4_once", "attack_rounds": "单轮"},
            "m3m4_sustained": {
                "profile": "m3m4_once",
                "template": "boundary_m3m4_once",
                "attack_rounds": "10轮持续（与 ack_once 窗口一致）",
            },
        },
        "ns3": DEFAULT_NS3,
        "simulator": DEFAULT_SIM,
        "runs": [],
    }

    # 实验臂设计：
    # ack_once: 持续10轮ACK攻击，仅PMAP_ACK（验证持续攻击恢复能力）
    # m3m4_once: 单轮M3M4攻击，PMAP vs PMAP_ACK对比（验证攻击有效性和单次恢复）
    # m3m4_sustained: 持续10轮M3M4丢弃，PMAP vs PMAP_ACK（与 ACK 臂对称的持续上行拦截）
    mapping = [
        # (arm_name, kind, protocols, boundary_profile)
        ("ack_once", "desync_ack_sustained", "PMAP_ACK", "ack_once"),
        ("m3m4_once", "desync_boundary_micro", "PMAP,PMAP_ACK", "m3m4_once"),
        ("m3m4_sustained", "desync_m3m4_sustained", "PMAP,PMAP_ACK", "m3m4_once"),
    ]
    for arm, kind, prots, profile in mapping:
        code = _run_swarm(arm, kind, prots, profile)
        manifest["runs"].append({"arm": arm, "exit_code": code, "out": str(OUT / arm)})
        if code != 0:
            (OUT / "MANIFEST.json").write_text(
                json.dumps(manifest, indent=2), encoding="utf-8"
            )
            print(f"[micro_desync] swarm failed arm={arm} code={code}", flush=True)
            return code

    round_payload: dict = {}
    for arm, _, _, _ in mapping:
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

    rc = subprocess.call([sys.executable, str(PLOT), "--results-root", str(OUT)], cwd=str(ROOT))
    if rc != 0:
        print(f"[micro_desync] plot exit {rc}", flush=True)

    manifest["finished_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[micro_desync] done -> {OUT}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
