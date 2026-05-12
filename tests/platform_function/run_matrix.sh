#!/bin/bash
# 机动应力测试矩阵包装脚本
# 用法: ./run_matrix.sh --list
#       ./run_matrix.sh --dry-run
#       ./run_matrix.sh --run-all --swarm-sizes 10 30
#       ./run_matrix.sh --single 0
# 说明: 直接使用 ns-3 Python 环境，避免 ns3 run 的参数拦截问题

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NS3_DIR="/home/zhang/ns/ns-allinone-3.43/ns-3.43"
BUILD_DIR="${NS3_DIR}/build"

export PYTHONPATH="${BUILD_DIR}/bindings/python:${SCRIPT_DIR}:${PYTHONPATH}"
export LD_LIBRARY_PATH="${BUILD_DIR}/lib:${LD_LIBRARY_PATH}"
export PATH="${BUILD_DIR}/lib:${PATH}"

cd "${SCRIPT_DIR}"
exec python3 run_mobility_stress_matrix.py "$@"
