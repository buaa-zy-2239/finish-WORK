# UAV D2Z 认证协议仿真平台

## 项目介绍

UAV D2Z 认证协议仿真平台是一个用于模拟和分析无人机（UAV）与地面站（ZSP）之间认证协议性能的综合平台。该平台支持多种认证协议的仿真，包括 PMAP、PMAP_ACK、STATIC_BASELINE 和 RLBA_UAV 等，并提供详细的性能分析和可视化功能。

### 主要功能

- **多种认证协议支持**：支持 PMAP、PMAP_ACK、STATIC_BASELINE、RLBA_UAV 等认证协议
- **丰富的仿真场景**：包括基线场景、边缘恢复、切换窗口认证、蜂群认证、机动应力测试等
- **实时性能分析**：提供认证成功率、消息效率、时间统计等详细指标
- **直观的可视化**：会话时间线、事件列表、性能指标图表等
- **WebSocket 实时推送**：实时推送认证事件和性能指标
- **可扩展的架构**：模块化设计，易于添加新的认证协议和仿真场景

## 技术栈

### 前端
- **框架**：React 18.0.0
- **HTTP 客户端**：Axios 1.4.0
- **构建工具**：Create React App
- **开发服务器**：默认端口 3000

### 后端
- **Web 框架**：FastAPI 2.3.0
- **HTTP 服务器**：Uvicorn
- **数据处理**：NumPy 1.24.0、Pandas 2.0.0
- **可视化**：Matplotlib 3.7.0、Plotly 5.14.0
- **测试**：Pytest 7.3.0
- **开发服务器**：默认端口 8000

### 依赖管理
- **前端**：npm
- **后端**：pip

## 项目结构

```
UAV/
├── Backend/           # 后端服务
│   ├── api/           # API 路由
│   ├── analysis/      # 数据分析模块
│   ├── core/          # 核心功能模块
│   ├── services/      # 服务模块
│   ├── app.py         # 主应用
│   └── config.py      # 配置文件
├── Frontend/          # 前端应用
│   ├── public/        # 静态资源
│   ├── src/           # 源代码
│   │   ├── components/ # 组件
│   │   ├── App.jsx    # 主应用组件
│   │   └── index.js   # 入口文件
│   ├── package.json   # 依赖配置
│   └── package-lock.json
├── experiments/       # 实验配置
├── logs/              # 日志目录
├── tasks/             # 仿真任务目录
├── tests/             # 测试文件
├── start_platform.sh  # 启动脚本
├── requirements.txt   # 后端依赖
└── README.md          # 项目说明
```

## 安装与启动

### 前置条件

- **Python 3.8+**
- **Node.js 14+**
- **npm 6+**

### 安装步骤

1. **克隆项目**

   ```bash
   git clone <repository-url>
   cd UAV
   ```

2. **安装后端依赖**

   ```bash
   pip install -r requirements.txt
   ```

3. **安装前端依赖**

   ```bash
   cd Frontend
   npm install
   cd ..
   ```

### 启动服务

使用一键启动脚本启动整个平台：

```bash
./start_platform.sh
```

**启动选项**：

- `BACKEND_PORT`：后端服务端口（默认 8000）
- `FRONTEND_PORT`：前端服务端口（默认 3000）
- `SKIP_FRONTEND`：设为 1 时仅启动后端
- `SKIP_BACKEND`：设为 1 时仅启动前端

**示例**：

```bash
# 使用自定义端口
BACKEND_PORT=8080 FRONTEND_PORT=3001 ./start_platform.sh

# 仅启动后端
SKIP_FRONTEND=1 ./start_platform.sh
```

## 使用指南

### 1. 仿真管理

通过前端界面（http://localhost:3000）的「仿真管理」页面创建和管理仿真任务：

1. **选择认证场景**：从下拉菜单中选择预设的仿真场景
2. **配置场景参数**：根据场景类型调整蜂群规模、密度、机动性等参数
3. **选择认证协议**：选择要测试的认证协议
4. **设置任务名称**：（可选）输入自定义任务名称
5. **创建任务**：点击「创建任务」按钮
6. **运行任务**：在任务列表中点击「运行」按钮启动仿真

### 2. 数据分析

通过前端界面的「分析仪表板」页面查看仿真结果：

1. **输入任务 ID**：（可选）输入特定任务的 ID 以查看该任务的结果
2. **查看性能指标**：查看认证成功率、消息效率、时间统计等指标
3. **分析会话列表**：查看详细的认证会话信息，包括状态、触发来源、耗时等
4. **查看时间线**：点击会话的「时间线」按钮，查看详细的认证过程时间线
5. **监控事件**：查看最新的认证事件

### 3. API 接口

后端提供以下 API 接口：

#### 健康检查
- **GET /api/v1/health**：检查服务健康状态

#### 仿真管理
- **POST /api/v1/simulation/create**：创建新的仿真任务
- **POST /api/v1/simulation/run/{task_id}**：运行指定的仿真任务
- **GET /api/v1/simulation/status/{task_id}**：获取任务状态
- **GET /api/v1/simulation/list**：获取任务列表

#### 数据分析
- **GET /api/v1/metrics/summary**：获取性能指标摘要
- **GET /api/v1/analysis/sessions**：获取认证会话列表
- **GET /api/v1/analysis/events**：获取认证事件列表
- **GET /api/v1/analysis/sessions/{uav_id}/{zsp_id}/timeline**：获取特定 UAV-ZSP 对的认证时间线

#### WebSocket
- **/ws/d2z-events**：实时推送认证事件
- **/ws/d2z-metrics**：实时推送性能指标

## 仿真场景

平台支持多种仿真场景，包括：

### 基线场景
- **基线 D2Z**：双 UAV、双 ZSP，航点移动，标准 PMAP 入网认证
- **PMAP_ACK 基线**：单 UAV 单塔，验证 D2Z_ACK 后双方再提交 PID/CRP 的正常路径

### 动态场景
- **边缘恢复**：单 UAV 沿固定巡检轨迹飞行，以距离 + RSSI 联合判据进入 edge 区域后触发认证
- **切换窗口认证**：单 UAV 在两个 ZSP 覆盖区之间穿行，发生切换时在切换窗口触发认证
- **编队起飞群飞**：多 UAV 按编队偏移跟随统一锚点航迹，模拟编队起飞/群飞
- **高速转场失联恢复**：单 UAV 高速转场，通过预设 loss window 模拟突发失联窗口

### 蜂群认证
- **蜂群认证（网络拥塞）**：多架 UAV 在任务启动窗口集中触发 D2Z 认证，用于观察并发接入压力
- **蜂群认证（计算敏感性）**：与网络拥塞场景保持相同蜂群拓扑，但在 ZSP 侧注入统一响应延迟

### 机动应力测试
- **机动应力测试**：测试不同机动性档位下的认证协议性能，支持调整网络规模、密度和 GM3D 应力档位

## 认证协议

平台支持以下认证协议：

- **PMAP**：经典协议，发完 M3/M4 即本地换 PID
- **PMAP_ACK**：会话冗余协议，收 ZSP 的 D2Z_ACK 后才换 PID
- **STATIC_BASELINE**：静态/预共享身份基线协议
- **RLBA_UAV**：三方 AKA 的平台映射版对照协议

## 测试

### 运行测试

```bash
# 运行所有测试
pytest

# 运行特定测试文件
pytest tests/test_api.py
```

### 测试覆盖

- **API 测试**：测试后端 API 接口的功能
- **日志解析测试**：测试日志解析功能
- **场景输入测试**：测试仿真场景配置的正确性
- **协议注册表测试**：测试协议注册和管理功能

## 配置

### 后端配置

后端配置文件位于 `Backend/config.py`，主要配置项包括：

- **APP_NAME**：应用名称
- **APP_VERSION**：应用版本
- **LOG_DIR**：日志目录
- **SIMULATION_TASKS_DIR**：仿真任务目录
- **NS3_INSTALL_PATH**：NS-3 仿真器安装路径
- **API_V1_PREFIX**：API 前缀
- **CORS_ORIGINS**：CORS 允许的源

### 前端配置

前端配置文件位于 `Frontend/package.json`，主要配置项包括：

- **dependencies**：前端依赖
- **scripts**：构建和运行脚本
- **proxy**：后端 API 代理配置

## 日志管理

仿真日志存储在 `logs/` 目录中，按任务 ID 组织。日志包含详细的认证事件、性能指标和错误信息，用于分析认证协议的性能和问题排查。

## 故障排除

### 常见问题

1. **前端无法连接后端**
   - 检查后端服务是否运行
   - 检查 `Frontend/package.json` 中的 proxy 配置
   - 检查网络防火墙设置

2. **仿真任务失败**
   - 检查 NS-3 仿真器是否正确安装
   - 检查仿真场景配置是否正确
   - 查看日志文件获取详细错误信息

3. **性能指标显示异常**
   - 检查日志文件是否存在
   - 检查日志格式是否正确
   - 检查后端服务是否正常运行

## 扩展与开发

### 添加新的认证协议

1. 在后端的协议注册表中注册新协议
2. 实现协议的核心逻辑
3. 在前端的协议选项中添加新协议

### 添加新的仿真场景

1. 在前端的 `SCENARIOS` 数组中添加新场景配置
2. 实现场景的拓扑生成逻辑
3. 在后端添加对应的场景处理逻辑

### 开发流程

1. **前端开发**：在 `Frontend/` 目录中进行开发，使用 `npm start` 启动开发服务器
2. **后端开发**：在 `Backend/` 目录中进行开发，使用 `python -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload` 启动开发服务器
3. **测试**：使用 `pytest` 运行测试，确保代码质量
4. **构建**：使用 `npm run build` 构建前端生产版本

## 贡献

欢迎对项目进行贡献，包括：

- 修复 bug
- 添加新功能
- 改进文档
- 优化性能

## 许可证

本项目采用 MIT 许可证。

## 联系方式

如有问题或建议，请通过以下方式联系：

- 项目维护者：[维护者姓名]
- 邮箱：[email@example.com]
- GitHub：[repository-url]

---

**版本：1.0.0**
**最后更新：2026-04-23**