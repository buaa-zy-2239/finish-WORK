#!/bin/bash
# 实验脚本包装器
# 用法: ./run_exp.sh exp_blockchain_10zsp_disabled.py
#       ./run_exp.sh exp_blockchain_10zsp_enabled.py

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NS3_DIR="/home/zhang/ns/ns-allinone-3.43/ns-3.43"
BUILD_DIR="${NS3_DIR}/build"

export PYTHONPATH="${BUILD_DIR}/bindings/python:${SCRIPT_DIR}:${PYTHONPATH}"
export LD_LIBRARY_PATH="${BUILD_DIR}/lib:${LD_LIBRARY_PATH}"
export PATH="${BUILD_DIR}/lib:${PATH}"

SCRIPT="$1"
shift 2>/dev/null || true

cd "${SCRIPT_DIR}"
exec python3 "${SCRIPT}" "$@"
