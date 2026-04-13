# UAV D2Z 安全认证协议仿真平台

面向 **无人机（UAV）与地面站（ZSP）** 的 **PMAP / PMAP_ACK** 入网认证仿真：在 **NS-3** 网络场景中运行协议实体，经 **FastAPI** 提供任务与日志 API，**React** 前端完成仿真管理与结果分析。

## 功能概览

- **协议**：经典 **PMAP**（M3/M4 后机端立即轮换 PID/CRP）与 **PMAP_ACK**（收 ZSP **D2Z_ACK** 后再提交轮换，支持 ACK 超时重试与会话冗余演示）。
- **攻击模型**：通过 `attack_model` / `desync_template` 在合法实体侧模拟信道级行为（如上行丢 M3/M4、下行拦 D2Z_ACK）；模板默认 **仅第一次认证** 触发去同步，便于观察恢复路径。
- **后端**：任务创建/运行、日志与指标、协议分析 API；可选 WebSocket 推送。
- **前端**：场景与协议选择、任务列表（含 **复制任务 ID**）、任务详情、分析看板。

## 仓库结构（节选）

| 路径 | 说明 |
|------|------|
| `Backend/` | FastAPI 应用（`app.py`）、路由、日志/仿真/分析服务 |
| `Frontend/` | React（CRA）单页应用 |
| `Entity/` | `PMAP_UAV`、`PMAP_ZSP` 等协议实体 |
| `Protocol/PMAP/` | 报文类型、二进制包、明文结构 |
| `Common/` | 攻击模型合并、`desync_attack_template`、日志框架等 |
| `Simulator/` | 与根目录 `simulator_builder.py` 协同的仿真构建逻辑 |
| `simulator_builder.py` | NS-3 仿真入口（`ns3 run` 调用），注入 UAV/ZSP 与场景 |
| `tests/` | `pytest` 用例（模板展开、日志解析等） |
| `start_platform.sh` | 本地一键启动后端 + 前端（开发模式） |

## 环境要求

- **Python 3**（建议 3.10+），已安装 **NS-3** 与 **cppyy**（仿真脚本依赖 `import ns`）。
- **Node.js** + **npm**（前端）。

### NS-3 安装说明

NS-3 的下载、依赖与编译步骤请以 **`docs/NS3环境配置.md`** 为准。

## NS3环境配置

系统：Ubuntu 22.04

+ 首先下载依赖组件

  ```
  sudo apt install -y g++ python3 cmake ninja-build git python3-dev pkg-config castxml
  ```

+ 下载cppyy库

  ```
  pip3 install --user cppyy
  ```

+ 源码下载与编译

  ```
  wget https://www.nsnam.org/release/ns-allinone-3.43.tar.bz2
  tar xjf ns-allinone-3.43.tar.bz2
  cd ns-allinone-3.43/ns-3.43
  ./ns3 configure --build-profile=debug --enable-examples --enable-tests --enable-python
  #观察是否输出有Python Bindings ON
  
  ./ns3 build #执行编译
  ./ns3 run first.py #python运行测试
  #输出如下
  At time +2s client sent 1024 bytes to 10.1.1.2 port 9
  At time +2.00369s server received 1024 bytes from 10.1.1.1 port 49153
  At time +2.00369s server sent 1024 bytes to 10.1.1.1 port 49153
  At time +2.00737s client received 1024 bytes from 10.1.1.2 port 9
  ```

  
在 **WSL / Linux** 下跑仿真时，仍需按该文档完成 NS-3 与 Python/cppyy 绑定，并在 **`Backend/config.py`** 中把 `NS3_INSTALL_PATH`、`NS3_COMMAND` 改成本机 `ns-3` 目录与 `ns3` 可执行文件路径。
- 后端运行至少需要：**FastAPI**、**Uvicorn**（`start_platform.sh` 会检查）。其余依赖按代码导入安装；仓库内 `requirements.txt` 可能与当前 FastAPI 栈不完全一致，若缺包可按报错补充安装。

示例：

```bash
pip install fastapi "uvicorn[standard]" pydantic numpy
```

前端依赖：

```bash
cd Frontend && npm install
```

## 快速启动

在项目根目录执行：

```bash
./start_platform.sh
```

默认：

- 后端：<http://127.0.0.1:8000>（API 前缀 `/api/v1`，健康检查 `/health`）
- 前端：<http://127.0.0.1:3000>（`Frontend/package.json` 中 `proxy` 指向后端）

常用环境变量（可选）：

| 变量 | 含义 |
|------|------|
| `BACKEND_PORT` | 后端端口，默认 `8000` |
| `FRONTEND_PORT` | 前端端口，默认 `3000` |
| `SKIP_FRONTEND=1` | 仅启动后端 |
| `SKIP_BACKEND=1` | 仅启动前端 |
| `BROWSER=none` | 禁止前端自动打开浏览器 |

## 配置说明

编辑 **`Backend/config.py`**（或后续改为环境变量）以匹配本机路径：

- **`SIMULATION_TASKS_DIR`**：仿真任务与 `config.json` 落盘目录（默认 `~/UAV_Simulation/tasks`）。
- **`NS3_INSTALL_PATH` / `NS3_COMMAND`**：本地 NS-3 安装与 `ns3` 可执行文件。
- **`SIMULATOR_SCRIPT`**：指向仓库根目录的 `simulator_builder.py`。
- **`LOG_DIR`**：与实体日志输出一致的目录。

修改后需重启后端进程。

## API 与前端

- REST：`/api/v1/simulation/...`、`/api/v1/analysis/...` 等（见 `Backend/api/routes/`）。
- 前端开发态通过 **proxy** 访问后端；生产构建时需将 `Frontend` 内 API 基地址与部署域名对齐。

## 测试

```bash
cd /path/to/UAV
python3 -m pytest tests/ -q
```

## 许可与贡献

未随仓库声明默认许可证；使用前请与维护者确认。欢迎通过 Issue / PR 贡献（建议先跑通 `pytest` 与一次完整仿真任务）。
