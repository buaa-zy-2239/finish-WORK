# UAV D2Z 认证协议仿真平台

<div align="center">

[![Platform](https://img.shields.io/badge/平台-UAV%20D2Z-blue)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://www.python.org/)
[![NS-3](https://img.shields.io/badge/NS-3-3.43-orange)](https://www.nsnam.org/)
[![React](https://img.shields.io/badge/React-18-cyan)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-red)](https://fastapi.tiangolo.com/)

**面向无人机与地面站（D2Z）认证协议的综合仿真平台，集成 NS-3 网络仿真、区块链技术与实时分析功能。**

[功能特性](#功能特性) • [系统架构](#系统架构) • [安装部署](#安装部署) • [快速开始](#快速开始) • [项目结构](#项目结构) • [协议说明](#协议说明) • [API 文档](#api-文档) • [配置指南](#配置指南) • [区块链集成](#区块链集成) • [攻击模型](#攻击模型) • [常见问题](#常见问题)

</div>

***

## 目录

- [项目概述](#项目概述)
- [功能特性](#功能特性)
- [系统架构](#系统架构)
- [安装部署](#安装部署)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [协议说明](#协议说明)
- [API 文档](#api-文档)
- [配置指南](#配置指南)
- [区块链集成](#区块链集成)
- [攻击模型](#攻击模型)
- [常见问题](#常见问题)

***

## 项目概述

UAV D2Z 认证协议仿真平台是一款面向无人机网络安全研究的仿真框架，用于评估和分析无人机（UAV）与地面站（ZSP）之间的设备认证协议。平台融合了基于 NS-3 的高保真网络仿真、协议实现、移动性建模以及基于区块链的身份管理。

### 核心研究方向

- **认证协议分析**：评估协议在各种网络条件下的效率、安全性与可靠性
- **移动性影响评估**：研究无人机移动模式对认证成功率的影响
- **去同步攻击建模**：模拟并分析协议对各类攻击向量的抵御能力
- **区块链集成**：探索无人机网络的去中心化身份管理方案

***

## 功能特性

### 核心能力

- **多协议支持**
  - PMAP（隐私保护相互认证协议）
  - PMAP\_ACK（带 D2Z 确认的 PMAP 变体）
  - RLBA-UAV（基于区块链的鲁棒轻量级认证）
  - RLBA-3WAY（三向握手机制）
  - 静态基线协议
- **网络仿真**
  - 基于 NS-3 的物理层仿真
  - 可配置信道模型（CSMA、无线等）
  - 数据包丢失建模（上行/下行、突发丢失）
  - 基于 RSSI 的切换决策
- **移动性模型**
  - 高斯-马尔可夫 3D 移动模型
  - 航点轨迹规划
  - 随机游走
  - 巡逻/编队/中转模式
  - 3GPP 信道场景（RMA、UMA 等）
- **区块链集成**
  - 以太坊兼容智能合约（UAVRegistry.sol）
  - PID（伪身份）轮换追踪
  - CRP（挑战-响应对）同步
  - 链上认证记录
- **攻击仿真**
  - 去同步攻击（上行/下行）
  - M3/M4 投递拦截
  - ACK 抑制（PMAP\_ACK）
  - 可配置攻击模板
- **实时分析仪表盘**
  - 认证指标可视化
  - 会话时间线分析
  - 协议状态机追踪
  - 成功率与距离关系分析

***

## 系统架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         UAV D2Z 仿真平台架构                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          前端 (React)                                  │    │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │    │
│  │  │ SimulationManager│  │AnalysisDashboard│  │ ProtocolConfig  │     │    │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘     │    │
│  │                                                                      │    │
│  │  WebSocket（实时事件/指标推送）                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                          │
│                                    ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                       后端 API (FastAPI)                               │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │    │
│  │  │ /simulation │  │  /analysis  │  │  /metrics   │  │  /events  │ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘ │    │
│  │                                                                      │    │
│  │  WebSocket 端点: /ws/d2z-events  /ws/d2z-metrics                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                          │
│                                    ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      仿真引擎 (NS-3)                                   │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │                    仿真构建器                                  │    │    │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│    │    │
│  │  │  │   实体层    │  │   协议层    │  │      移动性层        ││    │    │
│  │  │  │  UAV / ZSP │  │ PMAP / RLBA│  │  Gauss-Markov 3D   ││    │    │
│  │  │  └─────────────┘  └─────────────┘  └─────────────────────┘│    │    │
│  │  │                                                              │    │    │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│    │    │
│  │  │  │   网络层    │  │   区块链    │  │     会话追踪器       ││    │    │
│  │  │  │  配置      │  │   适配器    │  │                     ││    │    │
│  │  │  └─────────────┘  └─────────────┘  └─────────────────────┘│    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 组件说明

| 组件  | 技术栈                | 说明                         |
| --- | ------------------ | -------------------------- |
| 前端  | React 18           | 仿真管理与分析 Web 界面             |
| 后端  | FastAPI            | RESTful API 与 WebSocket 服务 |
| 仿真器 | NS-3.43            | 物理层与移动性网络仿真器               |
| 区块链 | Web3.py + Solidity | 以太坊集成与 PID 管理              |
| 协议  | Python             | PMAP、RLBA 协议实现             |
| 分析  | Python             | D2Z 协议效率分析器                |

***

## 安装部署

### 系统要求

- Ubuntu 22.04（推荐）
- Python 3.8+
- Node.js 16+ 和 npm
- NS-3.43
- 以太坊 RPC 端点（可选，用于区块链功能）

### 系统依赖

```bash
sudo apt install -y g++ python3 cmake ninja-build git python3-dev pkg-config castxml
```

### Python 依赖

```bash
cd /path/to/UAV
pip3 install --user -r requirements.txt
```

### NS-3 环境配置

**系统：Ubuntu 22.04**

- 首先安装编译依赖组件
  ```bash
  sudo apt install -y g++ python3 cmake ninja-build git python3-dev pkg-config castxml
  ```
- 安装 cppyy 库（Python-C++ 绑定）
  ```bash
  pip3 install --user cppyy
  ```
- 源码下载与编译
  ```bash
  # 下载 NS-3 源码包
  wget https://www.nsnam.org/release/ns-allinone-3.43.tar.bz2
  tar xjf ns-allinone-3.43.tar.bz2
  cd ns-allinone-3.43/ns-3.43

  # 配置项目（启用 Python 绑定）
  ./ns3 configure --build-profile=debug --enable-examples --enable-tests --enable-python
  # 观察输出是否包含 "Python Bindings ON"

  # 编译项目
  ./ns3 build

  # 运行测试验证
  ./ns3 run first.py
  # 预期输出如下：
  # At time +2s client sent 1024 bytes to 10.1.1.2 port 9
  # At time +2.00369s server received 1024 bytes from 10.1.1.1 port 49153
  # At time +2.00369s server sent 1024 bytes to 10.1.1.1 port 49153
  # At time +2.00737s client received 1024 bytes from 10.1.1.2 port 9
  ```

### 前端依赖

```bash
cd Frontend
npm install
```

### 后端配置

根据您的环境修改 `Backend/config.py` 中的路径配置：

```python
# NS-3 安装路径（请根据实际安装位置修改）
NS3_INSTALL_PATH = "/path/to/ns-allinone-3.43/ns-3.43"
NS3_COMMAND = "/path/to/ns-allinone-3.43/ns-3.43/ns3"

# 日志目录
LOG_DIR = "/path/to/UAV/logs"

# 仿真任务目录
SIMULATION_TASKS_DIR = "/path/to/UAV/tasks"
```

***

## 快速开始

### 启动平台

```bash
cd /path/to/UAV
./start_platform.sh
```

上述命令将启动：

- 后端 API：`http://127.0.0.1:8000`
- 前端界面：`http://127.0.0.1:3000`

### 环境变量

| 变量              | 默认值  | 说明         |
| --------------- | ---- | ---------- |
| `BACKEND_PORT`  | 8000 | 后端 API 端口  |
| `FRONTEND_PORT` | 3000 | 前端端口       |
| `SKIP_FRONTEND` | 0    | 设为 1 则跳过前端 |
| `SKIP_BACKEND`  | 0    | 设为 1 则跳过后端 |

### 运行基础仿真

1. 在浏览器中打开前端界面 `http://127.0.0.1:3000`
2. 选择仿真场景（如"移动性压力测试"）
3. 选择认证协议（如"PMAP"）
4. 配置蜂群规模和其他参数
5. 点击"创建任务"按钮
6. 点击"运行"按钮启动仿真
7. 在"结果分析"标签页查看仿真结果

***

## 项目结构

```
/path/to/UAV/
├── Backend/                    # FastAPI 后端服务
│   ├── api/
│   │   └── routes/            # API 路由
│   │       ├── simulation.py   # 仿真管理接口
│   │       ├── analysis.py     # 分析接口
│   │       ├── metrics.py      # 指标接口
│   │       ├── events.py       # 事件接口
│   │       └── health.py       # 健康检查
│   ├── core/
│   │   └── event_models.py     # 事件数据模型
│   ├── analysis/
│   │   └── protocol_analyzer.py # D2Z 协议分析器
│   ├── services/
│   │   ├── simulation_service.py
│   │   └── log_service.py
│   ├── app.py                  # FastAPI 应用入口
│   ├── config.py               # 配置文件
│   └── exceptions.py           # 自定义异常
│
├── Frontend/                   # React 前端
│   ├── src/
│   │   ├── components/
│   │   │   ├── SimulationManager.jsx
│   │   │   ├── AnalysisDashboard.jsx
│   │   │   └── ProtocolConfig.jsx
│   │   ├── hooks/
│   │   │   ├── useTasks.js
│   │   │   └── useAnalysis.js
│   │   ├── utils/
│   │   │   ├── scenarioGenerator.js
│   │   │   └── helpers.js
│   │   └── constants/
│   │       └── index.js
│   └── package.json
│
├── Entity/                     # 协议实体实现
│   ├── UAV/
│   │   ├── BaseUAV.py          # UAV 基类
│   │   ├── PMAPUAV.py          # PMAP UAV 实现
│   │   ├── RLBAUAV.py          # RLBA UAV 实现
│   │   └── StaticBaselineUAV.py # 基线 UAV
│   ├── ZSP/
│   │   ├── BaseZSP.py          # ZSP 基类
│   │   ├── PMAPZSP.py          # PMAP ZSP 实现
│   │   ├── RLBAZSP.py          # RLBA ZSP 实现
│   │   └── StaticBaselineZSP.py # 基线 ZSP
│   ├── User/
│   │   └── RLBAUser.py         # RLBA 用户节点
│   └── common/
│       ├── loss_models.py       # 突发丢失模型
│       ├── safe_executor.py     # 安全回调执行
│       └── session_tracker_mixin.py
│
├── Protocol/                   # 协议定义
│   ├── PMAP/
│   │   ├── Packet.py           # 数据包编解码
│   │   ├── PMAPPlaintext.py    # 明文格式
│   │   ├── MsgType.py          # 消息类型
│   │   ├── pmap_common.py      # 共享工具
│   │   ├── BinaryCodec.py      # 二进制编解码器
│   │   └── FieldCodec.py       # 字段编解码器
│   ├── RLBA/
│   │   ├── Packet.py           # RLBA 数据包格式
│   │   ├── MsgType.py          # 消息类型
│   │   └── Plaintext.py        # 明文格式
│   └── StaticBaseline/
│       ├── Packet.py
│       ├── MsgType.py
│       └── Plaintext.py
│
├── Mobility/                   # 移动性模型
│   ├── base.py                 # 基础移动性辅助类
│   ├── mobility.py              # 移动性工厂
│   ├── gauss_markov.py         # 高斯-马尔可夫模型
│   ├── gauss_markov_3d_model.py # 3D 扩展
│   └── waypoint_builder.py     # 航点生成器
│
├── Simulator/                  # 仿真基础设施
│   ├── network_config.py       # 网络配置
│   ├── session_tracker.py      # 会话追踪
│   ├── session_record.py       # 会话记录
│   ├── metrics_collector.py    # 指标收集
│   ├── channel_models.py       # 信道模型
│   └── simulator_builder.py     # 主仿真构建器
│
├── BlockChain/                 # 区块链集成
│   ├── Blockchain.py           # Web3 适配器
│   ├── BlockchainInterface.py   # 接口定义
│   └── UAVRegistry.sol         # 以太坊智能合约
│
├── KeyGen/                     # 密钥生成
│   ├── BaseKeyGenerator.py     # 基类
│   ├── PUFGenerator.py        # PUF 密钥生成
│   ├── ECCGenerator.py         # ECC 密钥生成
│   └── KyberGenerator.py       # Kyber（后量子）
│
├── Caculator/                  # 密码学计算器
│   ├── ChaoticMap.py           # 混沌映射运算
│   ├── Hash.py                 # 哈希函数
│   └── ChameleonHashCaculator.py
│
├── Common/                     # 共享工具
│   ├── scenario_inputs.py      # 场景配置
│   ├── protocol_registry.py    # 协议注册表
│   ├── attack_model.py         # 攻击模型工具
│   ├── desync_attack_template.py # 去同步攻击模板
│   ├── desync_experiment_hooks.py
│   ├── logging_framework.py    # 日志框架
│   ├── crp_chain_codec.py      # CRP 编码
│   └── null_logger.py
│
├── tests/                      # 测试套件
│   ├── test_*.py               # 各类测试
│   └── test_scenario_inputs.py
│
├── docs/
│   └── NS3环境配置.md          # NS-3 安装指南
│
├── requirements.txt            # Python 依赖
├── start_platform.sh           # 平台启动脚本
└── simulator_builder.py        # 主仿真入口
```

***

## 协议说明

### PMAP（隐私保护相互认证协议）

PMAP 是一款专为无人机网络设计的轻量级认证协议，其消息流程如下：

```
UAV                          ZSP
  │                            │
  │──── M1 (PID, 加密) ──────▶│  挑战
  │                            │
  │◀── M2 (NI, NS, 加密) ────│  响应
  │                            │
  │──── M3/M4 (NI, NS, f) ──▶│  CRP 更新
  │                            │
  │✓ PID 已更新                │
```

**变体说明：**

- **PMAP**：标准 4 消息交换
- **PMAP\_ACK**：扩展 D2Z 确认机制，确保可靠投递

### RLBA（基于区块链的鲁棒轻量级认证）

RLBA 结合基于 PUF 的认证与基于区块链的 PID 管理：

```
UAV                          ZSP                       区块链
  │                            │                            │
  │──── 认证请求 ────────────▶│                            │
  │                            │──── PID 更新 ─────────────▶│
  │                            │                            │
  │◀── 认证响应 ←────────────│◀── PID 确认 ←─────────────│
  │                            │                            │
```

**核心特性：**

- 基于 PUF 的挑战-响应对生成
- 链上 PID 轮换
- 三向握手变体（RLBA-3WAY）

### 静态基线

作为对比基准的参考实现，用于与优化协议进行性能比较。

***

## API 文档

### 基础 URL

```
http://localhost:8000/api/v1
```

### 接口列表

#### 仿真管理

| 方法   | 端点                             | 说明      |
| ---- | ------------------------------ | ------- |
| POST | `/simulation/create`           | 创建仿真任务  |
| POST | `/simulation/run/{task_id}`    | 运行仿真任务  |
| GET  | `/simulation/status/{task_id}` | 获取任务状态  |
| GET  | `/simulation/list`             | 列出所有任务  |
| GET  | `/simulation/config/{task_id}` | 获取任务配置  |
| GET  | `/simulation/protocols`        | 列出支持的协议 |

#### 分析接口

| 方法  | 端点                                         | 说明      |
| --- | ------------------------------------------ | ------- |
| GET | `/analysis/metrics`                        | 获取认证指标  |
| GET | `/analysis/events`                         | 获取协议事件  |
| GET | `/analysis/sessions`                       | 获取会话详情  |
| GET | `/analysis/sessions/{session_id}/timeline` | 获取会话时间线 |

#### WebSocket

| 端点                | 说明        |
| ----------------- | --------- |
| `/ws/d2z-events`  | D2Z 事件实时流 |
| `/ws/d2z-metrics` | 实时指标推送    |

### 请求/响应示例

#### 创建仿真任务

```bash
curl -X POST http://localhost:8000/api/v1/simulation/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "测试仿真",
    "duration": 30,
    "protocol": "PMAP",
    "uavs": [...],
    "zsps": [...],
    "enable_blockchain": false
  }'
```

#### 响应示例

```json
{
  "success": true,
  "task_id": "sim_20240501_120000_abc12345",
  "config_file": "/path/to/config.json",
  "message": "仿真任务创建成功"
}
```

***

## 配置指南

### 仿真配置 schema

```json
{
  "task_id": "sim_xxx",
  "name": "仿真名称",
  "duration": 30,
  "protocol": "PMAP",
  "uavs": [
    {
      "id": 0,
      "mobility": {
        "type": "gauss_markov_3d",
        "alpha": 0.99,
        "mean_velocity": 5.0
      },
      "auth_trigger": {
        "time_offsets_s": [0, 10, 20],
        "initial_on_connect": true
      }
    }
  ],
  "zsps": [
    {
      "id": 0,
      "position": [0, 0, 100]
    }
  ],
  "channel": {
    "type": "CSMA",
    "datarate": "100Mbps"
  },
  "attack_model": {
    "desync_template": "uplink_rotation_drop",
    "desync_attack_first_auth_only": true
  },
  "enable_blockchain": false
}
```

### 攻击模型模板

| 模板                      | 说明                                        |
| ----------------------- | ----------------------------------------- |
| `uplink_rotation_drop`  | ZSP 丢弃 M3/M4（intercept\_m3\_m4\_delivery） |
| `downlink_d2z_ack_drop` | ZSP 抑制 ACK（PMAP\_ACK）或 SUCCESS（RLBA）      |
| `boundary_m3m4_once`    | 每 UAV 单次 M3/M4 丢弃                         |
| `boundary_ack_once`     | 每 UAV 单次 ACK 抑制                           |

***

## 区块链集成

### 智能合约

平台使用 `UAVRegistry.sol` 进行链上无人机身份管理：

```solidity
contract UAVRegistry {
    // PID -> UAVInfo 映射
    mapping(bytes32 => UAVInfo) private registry;

    // 带 CRP 的 PID 更新
    function updatePID(
        bytes32 oldPID,
        bytes32 newPID,
        uint256 challenge,
        uint256 response
    ) public;

    // UAV 有效性验证
    function isValidUAV(bytes32 pid) public view returns (bool);
}
```

### 配置说明

启用区块链功能需确保：

1. 以太坊 RPC 端点可访问（默认：`http://127.0.0.1:8545`）
2. 智能合约已部署
3. 仿真配置中设置 `enable_blockchain: true`

***

## 攻击模型

### 去同步攻击模板

平台支持多种去同步攻击配置：

| 模板组合                    | 说明                                    |
| ----------------------- | ------------------------------------- |
| `uplink_rotation_drop`  | ZSP 丢弃上行 M3/M4，导致 UAV 无法更新 PID        |
| `downlink_d2z_ack_drop` | PMAP\_ACK 抑制 D2Z\_ACK；RLBA 抑制 SUCCESS |
| `boundary_m3m4_once`    | 边界攻击：每 UAV 有限次 M3/M4 丢弃               |
| `boundary_ack_once`     | 边界攻击：每 UAV 有限次 ACK 抑制                 |

### 攻击参数

```python
{
    "desync_template": "uplink_rotation_drop,downlink_d2z_ack_drop",
    "desync_attack_first_auth_only": True,  # 每 UAV 每种攻击仅一次
    "desync_attack_every_round": False,       # 持续攻击模式
    "desync_attack_min_completed_sessions": 0  # 攻击生效前的最小完成会话数
}
```

***

## 常见问题

### NS-3 未找到

```
Error: ns3 command not found
```

**解决方案：** 确认 `Backend/config.py` 中的 `NS3_COMMAND` 指向正确的 NS-3 安装路径。

### Python 绑定不可用

```
Error: No module named 'ns'
```

**解决方案：** 重新编译 NS-3 以启用 Python 绑定：

```bash
cd /path/to/ns-allinone-3.43/ns-3.43
./ns3 configure --build-profile=debug --enable-python
./ns3 build
```

### 前端构建失败

**解决方案：** 清除 node\_modules 并重新安装：

```bash
cd Frontend
rm -rf node_modules package-lock.json
npm install
```

### 区块链连接失败

```
Error: Blockchain RPC not reachable
```

**解决方案：** 启动以太坊节点（如 Ganache）或确认 RPC URL 配置正确。

### 日志说明

仿真日志存储在 `/path/to/UAV/logs/` 目录，包含：

- `events.jsonl` - 协议事件
- `session_*.json` - 会话记录
- `metrics.json` - 聚合指标

###
