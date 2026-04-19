#!/usr/bin/env bash
# S04：组合应力 — aggressive 机动 + RSSI/burst；N 子集控制成本。
# 机动约 12±7 m/s（aggressive）+ 与 S03 相同信道应力；种子默认与 S01–S03 同为 12 个。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

NS3_BIN="${NS3_BIN:-/home/zhang/ns/ns-allinone-3.43/ns-3.43/ns3}"
SIMULATOR="${SIMULATOR:-$ROOT/simulator_builder.py}"
OUT="${OUT_S04:-$ROOT/experiments/results_repro_s04}"
# 与 S01–S03 默认对齐：12 个独立种子（可通过环境变量 SEEDS 覆盖）
SEEDS="${SEEDS:-20260417,20260418,20260419,20260420,20260421,20260422,20260423,20260424,20260425,20260426,20260427,20260428}"

mkdir -p "$OUT"
python3 "$ROOT/experiments/swarm_unified_scenario_experiment.py" \
  --sizes 10,30 \
  --protocols PMAP,PMAP_ACK \
  --motion-modes gauss_markov_3d \
  --seeds "$SEEDS" \
  --densities low \
  --out-root "$OUT" \
  --between-sleep 2.0 \
  --academic-profile twc2025_elevation_aware \
  --gm3d-stress aggressive \
  --rssi-loss-enabled \
  --burst-loss-enabled \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR" \
  --resume

python3 "$ROOT/experiments/reproducible/aggregate_and_plot.py" \
  --results-root "$OUT" \
  --charts-dir "$OUT/charts" \
  --filter-density 1 \
  --filter-gm aggressive

echo "[done] S04 results under $OUT"
