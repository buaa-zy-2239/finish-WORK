#!/usr/bin/env bash
# S01：主可扩展性 — N×ρ×协议×独立种子（统计用）。默认 12 种子，可用 SEEDS 覆盖为 20–30。
# 机动：gauss_markov_3d + --gm3d-stress nominal（均值速度约 5 m/s、σ≈5 m/s，见 swarm 内 GM3D_STRESS_PRESETS）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

NS3_BIN="${NS3_BIN:-/home/zhang/ns/ns-allinone-3.43/ns-3.43/ns3}"
SIMULATOR="${SIMULATOR:-$ROOT/simulator_builder.py}"
OUT="${OUT_S01:-$ROOT/experiments/results_repro_s01}"
# 12 个独立种子；论文级可设 SEEDS 为 30 个逗号分隔整数
SEEDS="${SEEDS:-20260417,20260418,20260419,20260420,20260421,20260422,20260423,20260424,20260425,20260426,20260427,20260428}"

mkdir -p "$OUT"
python3 "$ROOT/experiments/swarm_unified_scenario_experiment.py" \
  --sizes 10,30,50 \
  --protocols PMAP,PMAP_ACK \
  --motion-modes gauss_markov_3d \
  --seeds "$SEEDS" \
  --densities low,medium,high \
  --out-root "$OUT" \
  --between-sleep 2.0 \
  --academic-profile twc2025_elevation_aware \
  --gm3d-stress nominal \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR" \
  --resume

python3 "$ROOT/experiments/reproducible/aggregate_and_plot.py" \
  --results-root "$OUT" \
  --charts-dir "$OUT/charts"

echo "[done] S01 results under $OUT"
