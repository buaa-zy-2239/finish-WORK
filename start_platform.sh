#!/usr/bin/env bash
#
# 一键启动 UAV 仿真平台：后端 FastAPI + 前端 React（开发模式）
# 用法：在项目根目录执行  ./start_platform.sh
# 停止：Ctrl+C（会尝试结束子进程）
#
# 环境变量（可选）：
#   BACKEND_PORT   默认 8000
#   FRONTEND_PORT  默认 3000（Create React App 通过 PORT 传递）
#   SKIP_FRONTEND  设为 1 时仅启动后端
#   SKIP_BACKEND   设为 1 时仅启动前端
#

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"
SKIP_FRONTEND="${SKIP_FRONTEND:-0}"
SKIP_BACKEND="${SKIP_BACKEND:-0}"

say() { printf '%s\n' "$*"; }

check_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    say "错误: 未找到命令「$1」，请先安装。"
    exit 1
  fi
}

cleanup() {
  say ""
  say "正在停止服务..."
  if [[ -n "${BACKEND_PID:-}" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [[ -n "${FRONTEND_PID:-}" ]] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  # 子进程树（如 node 子进程）
  pkill -P $$ 2>/dev/null || true
  say "已退出。"
}

trap cleanup EXIT INT TERM HUP

check_cmd python3
if [[ "$SKIP_FRONTEND" != "1" ]]; then
  check_cmd npm
  if [[ ! -d "$ROOT/Frontend/node_modules" ]]; then
    say "错误: 未找到 Frontend/node_modules，请先执行:"
    say "  cd \"$ROOT/Frontend\" && npm install"
    exit 1
  fi
fi

if ! python3 -c "import uvicorn" 2>/dev/null; then
  say "错误: 当前 Python 环境未安装 uvicorn。"
  say "可执行: pip install uvicorn fastapi \"uvicorn[standard]\""
  exit 1
fi

if [[ "$SKIP_BACKEND" != "1" ]]; then
  if python3 -c "import fastapi" 2>/dev/null; then :; else
    say "错误: 未安装 fastapi。可执行: pip install fastapi"
    exit 1
  fi
fi

cd "$ROOT"

say "=========================================="
say "  UAV 仿真平台 — 一键启动"
say "=========================================="
say "项目根目录: $ROOT"
say ""

if [[ "$SKIP_BACKEND" != "1" ]]; then
  say "启动后端: http://127.0.0.1:${BACKEND_PORT}  (API: /api/v1/..., 健康检查: /health)"
  (
    cd "$ROOT/Backend"
    export PYTHONPATH=.
    exec python3 -m uvicorn app:app --host 0.0.0.0 --port "$BACKEND_PORT"
  ) &
  BACKEND_PID=$!
else
  say "已跳过后端 (SKIP_BACKEND=1)"
fi

if [[ "$SKIP_FRONTEND" != "1" ]]; then
  say "启动前端: http://127.0.0.1:${FRONTEND_PORT}"
  say "（首次会自动打开浏览器；可设置 BROWSER=none 禁止）"
  (
    cd "$ROOT/Frontend"
    export PORT="$FRONTEND_PORT"
    export BROWSER="${BROWSER:-}"
    exec npm start
  ) &
  FRONTEND_PID=$!
else
  say "已跳过前端 (SKIP_FRONTEND=1)"
fi

say ""
say "按 Ctrl+C 停止全部服务。"
say "=========================================="

# 等待任一前台相关子进程结束则触发 EXIT 清理
wait || true
