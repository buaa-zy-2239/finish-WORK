#!/usr/bin/env bash
# S02：机动应力 — 仅调 GM3D 档位（α/速度统计），信道与 S01 nominal 一致；ρ=low 以突出机动效应。
# 三档速度量级（约）：conservative 3±2 m/s；nominal 5±5 m/s；aggressive 12±7 m/s。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

NS3_BIN="${NS3_BIN:-/home/zhang/ns/ns-allinone-3.43/ns-3.43/ns3}"
SIMULATOR="${SIMULATOR:-$ROOT/simulator_builder.py}"
OUT="${OUT_S02:-$ROOT/experiments/results_repro_s02}"
SEEDS="${SEEDS:-20260417,20260418,20260419,20260420,20260421,20260422,20260423,20260424}"

mkdir -p "$OUT"
for GM in conservative nominal aggressive; do
  echo "=== gm3d-stress=$GM ==="
  python3 "$ROOT/experiments/swarm_unified_scenario_experiment.py" \
    --sizes 10,30 \
    --protocols PMAP,PMAP_ACK \
    --motion-modes gauss_markov_3d \
    --seeds "$SEEDS" \
    --densities low \
    --out-root "$OUT" \
    --between-sleep 2.0 \
    --academic-profile twc2025_elevation_aware \
    --gm3d-stress "$GM" \
    --ns3 "$NS3_BIN" \
    --simulator "$SIMULATOR" \
    --resume
done

python3 "$ROOT/experiments/reproducible/aggregate_and_plot.py" \
  --results-root "$OUT" \
  --charts-dir "$OUT/charts" \
  --filter-density 1

echo "[done] S02 results under $OUT"
