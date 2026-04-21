#!/usr/bin/env bash
# S03：信道应力 — RSSI 映射丢包 + burst（与 academic profile 一致）；GM nominal；ρ=low。
# 机动与 S01 主表一致（gauss_markov_3d nominal），便于单独看「信道恶化」效应。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

NS3_BIN="${NS3_BIN:-/home/zhang/ns/ns-allinone-3.43/ns-3.43/ns3}"
SIMULATOR="${SIMULATOR:-$ROOT/simulator_builder.py}"
OUT="${OUT_S03:-$ROOT/experiments/results_repro_s03-test}"
SEEDS="${SEEDS:-20260417,20260418,20260419,20260420,20260421,20260422,20260423,20260424}"

mkdir -p "$OUT"
python3 "$ROOT/experiments/swarm_unified_scenario_experiment.py" \
  --sizes 10,30,50 \
  --protocols PMAP,PMAP_ACK \
  --motion-modes gauss_markov_3d \
  --seeds "$SEEDS" \
  --densities low \
  --out-root "$OUT" \
  --between-sleep 2.0 \
  --academic-profile twc2025_elevation_aware \
  --gm3d-stress nominal \
  --rssi-loss-enabled \
  --burst-loss-enabled \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR" \
  --resume

python3 "$ROOT/experiments/reproducible/aggregate_and_plot.py" \
  --results-root "$OUT" \
  --charts-dir "$OUT/charts" \
  --filter-density 1

echo "[done] S03 results under $OUT"
