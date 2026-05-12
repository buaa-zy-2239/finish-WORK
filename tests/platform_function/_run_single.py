"""
单个实验子进程执行器
供 run_mobility_stress_matrix.py 以 subprocess 方式调用
用法: python3 _run_single.py <config_path> <output_path>
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def main():
    if len(sys.argv) < 3:
        print("用法: python3 _run_single.py <config_path> <output_path>", file=sys.stderr)
        sys.exit(1)

    config_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    with open(config_path, "r") as f:
        config = json.load(f)

    meta = config.pop("_meta", {})

    from simulator_builder import SimulationBuilderEnhanced

    builder = SimulationBuilderEnhanced(config_dict=config)
    result = builder.run()

    result["cid"] = output_path.stem.replace("result_", "", 1)
    result["meta"] = meta

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)

    if result.get("status") in ("success", "completed"):
        stats = result.get("statistics", {})
        st_metrics = stats.get("session_tracker_metrics", {})
        auth = st_metrics.get("authentication", {})
        success_rate = auth.get("success_rate_percent", "N/A")
        print(f"  status=success rate={success_rate}%")
    else:
        print(f"  status={result.get('status', 'unknown')}")


if __name__ == "__main__":
    main()
