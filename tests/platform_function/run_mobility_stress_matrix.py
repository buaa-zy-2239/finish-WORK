"""
机动应力测试参数矩阵批处理编排器
支持全量/选择性运行、断点续跑、配置导出
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from param_matrix import (
    REDUCED_SWARM_SIZES,
    REDUCED_DENSITY_OPTIONS,
    GM3D_STRESS_OPTIONS, REDUCED_GM3D_STRESS_OPTIONS,
    G3PP_SCENARIO_OPTIONS,
    CARRIER_FREQUENCY_OPTIONS, REDUCED_CARRIER_FREQUENCY_OPTIONS,
    get_all_combinations,
    format_combination_id,
)

RESULTS_DIR = ROOT / "mobility_stress_results"
CONFIG_DIR = RESULTS_DIR / "configs"
CHECKPOINT_FILE = RESULTS_DIR / "checkpoint.json"


def ensure_dirs():
    RESULTS_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)


def load_checkpoint() -> set:
    if CHECKPOINT_FILE.exists():
        with open(CHECKPOINT_FILE, "r") as f:
            return set(json.load(f))
    return set()


def save_checkpoint(completed_ids: set):
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump(sorted(completed_ids), f, indent=2)


def save_config(combo: dict):
    cid = format_combination_id(combo)
    config_path = CONFIG_DIR / f"config_{cid}.json"

    if config_path.exists():
        return config_path

    cfg = combo["config"]
    cfg["_meta"] = {
        "swarm_size": combo["swarm_size"],
        "density": combo["density"],
        "stress_level": combo["stress_level"],
        "scenario": combo["scenario"],
        "carrier_freq_hz": combo["carrier_freq_hz"],
        "generated_at": datetime.now().isoformat(),
    }

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    return config_path


def run_single_experiment(combo: dict, dry_run: bool = False) -> dict:
    """在独立子进程中运行单个实验组合"""
    cid = format_combination_id(combo)
    config_path = save_config(combo)

    if dry_run:
        result = {
            "status": "dry_run",
            "cid": cid,
            "config_file": str(config_path),
            "experiment_name": combo["config"]["name"],
            "meta": {
                "swarm_size": combo["swarm_size"],
                "density": combo["density"],
                "stress_level": combo["stress_level"],
                "scenario": combo["scenario"],
                "carrier_freq_hz": combo["carrier_freq_hz"],
            },
        }
        return result

    print(f"\n{'='*70}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 运行实验: {cid}")
    print(f"  名称: {combo['config']['name']}")
    print(f"  UAV: {combo['swarm_size']}, ZSP: {len(combo['config']['zsps'])}")
    print(f"  速度: {combo['stress_level']}, 场景: {combo['scenario']}")
    print(f"  频率: {combo['carrier_freq_hz']/1e9:.1f}GHz, 密度: {combo['density']}/km²")
    print(f"{'='*70}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = RESULTS_DIR / f"result_{cid}_{timestamp}.json"

    try:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "_run_single.py"),
             str(config_path), str(output_path)],
            capture_output=True, text=True, timeout=180,
            env=None,
            cwd=str(ROOT),
        )

        print(proc.stdout, end="")
        if proc.stderr:
            print(f"  stderr: {proc.stderr[:500]}")

        if proc.returncode != 0:
            print(f"  ✗ 子进程退出码: {proc.returncode}")
            return {"status": "subprocess_error", "cid": cid,
                    "returncode": proc.returncode, "stderr": proc.stderr[:1000]}

        if output_path.exists():
            with open(output_path, "r") as f:
                result = json.load(f)
            rate = result.get("statistics", {}).get(
                "session_tracker_metrics", {}).get(
                "authentication", {}).get("success_rate_percent", "N/A")
            if result.get("status") in ("success", "completed"):
                print(f"  ✓ 完成 | 认证成功率: {rate}%")
            else:
                print(f"  ✗ 失败: {result.get('status', 'unknown')}")
            return result
        else:
            print(f"  ✗ 未生成结果文件")
            return {"status": "no_output", "cid": cid}

    except subprocess.TimeoutExpired:
        print(f"  ✗ 超时 (600s)")
        return {"status": "timeout", "cid": cid}
    except Exception as e:
        print(f"  ✗ 异常: {e}")
        return {"status": "error", "cid": cid, "error": str(e)}


def filter_combinations(
    combinations,
    swarm_sizes=None,
    densities=None,
    stress_levels=None,
    scenarios=None,
    freqs=None,
    resume: bool = True,
):
    """按参数过滤组合"""
    completed_ids = load_checkpoint() if resume else set()

    filtered = []
    for combo in combinations:
        cid = format_combination_id(combo)

        if resume and cid in completed_ids:
            continue
        if swarm_sizes and combo["swarm_size"] not in swarm_sizes:
            continue
        if densities and combo["density"] not in densities:
            continue
        if stress_levels and combo["stress_level"] not in stress_levels:
            continue
        if scenarios and combo["scenario"] not in scenarios:
            continue
        if freqs and combo["carrier_freq_hz"] not in freqs:
            continue

        filtered.append(combo)

    return filtered


def print_summary(all_combos, completed_ids):
    total = len(all_combos)
    done = len(completed_ids)
    remaining = total - done
    pct = done / total * 100 if total > 0 else 0

    print(f"\n{'='*50}")
    print(f"实验进度汇总")
    print(f"{'='*50}")
    print(f"  总组合数:    {total}")
    print(f"  已完成:      {done} ({pct:.1f}%)")
    print(f"  剩余:        {remaining}")
    print(f"{'='*50}\n")


def main():
    parser = argparse.ArgumentParser(
        description="机动应力测试参数矩阵批处理实验编排器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 查看精简组合 (默认)
  python run_mobility_stress_matrix.py --list

  # 查看全量组合
  python run_mobility_stress_matrix.py --list --mode full

  # 生成所有配置（不运行）
  python run_mobility_stress_matrix.py --dry-run

  # 运行精简实验集（默认, 108组）
  python run_mobility_stress_matrix.py --run-all

  # 运行全部720组
  python run_mobility_stress_matrix.py --run-all --mode full

  # 仅运行某种蜂群规模
  python run_mobility_stress_matrix.py --run-all --swarm-sizes 10 50

  # 仅运行特定参数筛选
  python run_mobility_stress_matrix.py --run-all --scenarios rma

  # 仅运行特定索引的单个实验
  python run_mobility_stress_matrix.py --single 0

  # 重置 checkpoint（重新运行所有）
  python run_mobility_stress_matrix.py --reset
        """,
    )

    parser.add_argument("--mode", type=str, default="reduced",
                        choices=["reduced", "full"],
                        help="实验模式: reduced(默认, 108组) 或 full(720组)")
    parser.add_argument("--list", action="store_true", help="列出所有参数组合")
    parser.add_argument("--dry-run", action="store_true", help="仅生成配置，不运行仿真")
    parser.add_argument("--run-all", action="store_true", help="运行所有符合条件的实验")
    parser.add_argument("--single", type=int, default=None, help="运行单个实验（按索引）")
    parser.add_argument("--reset", action="store_true", help="重置 checkpoint，重新运行所有")
    parser.add_argument("--summary", action="store_true", help="显示实验进度汇总")

    parser.add_argument("--swarm-sizes", type=int, nargs="*", help="筛选蜂群规模")
    parser.add_argument("--densities", type=int, nargs="*", help="筛选密度")
    parser.add_argument("--stress-levels", type=str, nargs="*",
                        choices=["hover", "conservative", "nominal", "aggressive", "high_speed"],
                        help="筛选速度档位")
    parser.add_argument("--scenarios", type=str, nargs="*",
                        choices=["uma", "umi", "rma"],
                        help="筛选 3GPP 场景")
    parser.add_argument("--freqs", type=float, nargs="*",
                        help="筛选载波频率 (Hz)")
    parser.add_argument("--no-resume", action="store_true", help="忽略 checkpoint，重新运行")

    args = parser.parse_args()
    ensure_dirs()

    if args.reset:
        if CHECKPOINT_FILE.exists():
            CHECKPOINT_FILE.unlink()
            print("✓ Checkpoint 已重置")
        return

    all_combinations = get_all_combinations(mode=args.mode)
    stress_opts_for_label = REDUCED_GM3D_STRESS_OPTIONS if args.mode == "reduced" else GM3D_STRESS_OPTIONS
    freq_opts_for_label = REDUCED_CARRIER_FREQUENCY_OPTIONS if args.mode == "reduced" else CARRIER_FREQUENCY_OPTIONS

    if args.list:
        print(f"\n{'='*90}")
        print(f"参数矩阵组合一览（{args.mode}模式，共 {len(all_combinations)} 组）")
        print(f"{'='*90}")
        print(f"  {'Idx':>4s} | {'Swarm':>5s} | {'Density':>8s} | {'Speed':>14s} | {'Scenario':>6s} | {'Freq':>10s}")
        print(f"  {'-'*4} | {'-'*5} | {'-'*8} | {'-'*14} | {'-'*6} | {'-'*10}")
        for combo in all_combinations:
            f_ghz = combo["carrier_freq_hz"] / 1e9
            stress_label = next(
                o["label"] for o in stress_opts_for_label if o["value"] == combo["stress_level"]
            )
            print(
                f"  {combo['index']:>4d} | "
                f"{combo['swarm_size']:>5d} | "
                f"{combo['density']:>3d}/km²   | "
                f"{stress_label[:14]:>14s} | "
                f"{combo['scenario'].upper():>6s} | "
                f"{f_ghz:.1f}GHz"
            )
        return

    if args.summary:
        completed_ids = load_checkpoint()
        print_summary(all_combinations, completed_ids)
        return

    if args.dry_run:
        filtered = filter_combinations(
            all_combinations,
            args.swarm_sizes,
            args.densities,
            args.stress_levels,
            args.scenarios,
            args.freqs,
            resume=False,
        )
        print(f"\n准备生成 {len(filtered)} 个实验配置...")
        for combo in filtered:
            config_path = save_config(combo)
            print(f"  ✓ {format_combination_id(combo)} -> {config_path.name}")
        print(f"\n全部配置已保存至: {CONFIG_DIR}/")
        return

    if args.single is not None:
        if args.single < 0 or args.single >= len(all_combinations):
            print(f"错误: 索引 {args.single} 超出范围 [0, {len(all_combinations)-1}]")
            sys.exit(1)
        combo = all_combinations[args.single]
        result = run_single_experiment(combo, dry_run=False)
        if result.get("status") not in ("engine_unavailable", "error"):
            completed_ids = load_checkpoint()
            completed_ids.add(format_combination_id(combo))
            save_checkpoint(completed_ids)
        return

    if args.run_all:
        filtered = filter_combinations(
            all_combinations,
            args.swarm_sizes,
            args.densities,
            args.stress_levels,
            args.scenarios,
            args.freqs,
            resume=not args.no_resume,
        )

        completed_ids = load_checkpoint()
        print(f"\n总计 {len(all_combinations)} 组组合，已完成 {len(completed_ids)} 组")
        print(f"本次将运行 {len(filtered)} 组")

        if not filtered:
            print("没有需要运行的实验。使用 --reset 重置 checkpoint。")
            return

        for combo in filtered:
            cid = format_combination_id(combo)
            result = run_single_experiment(combo, dry_run=False)
            if result.get("status") not in ("engine_unavailable", "error"):
                completed_ids.add(cid)
                save_checkpoint(completed_ids)
            elif result.get("status") == "engine_unavailable":
                print("仿真引擎不可用，退出批处理。")
                print("请在有 ns-3 的环境中运行。")
                break

        print_summary(all_combinations, load_checkpoint())
        return

    parser.print_help()


if __name__ == "__main__":
    main()
