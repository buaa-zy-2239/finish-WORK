# 实验体系说明（单一文档）

本文档为 **`experiments/` 下实验与设计的唯一权威说明**：运行入口、产物目录、统计复现、场景与威胁模型、顶会双臂协议（英文）均在此维护。历史上分散的 `SCALABILITY_DESIGN.md`、`D2Z_SCENARIO_DESIGN.md`、`DESYNC_BOUNDARY_DESIGN.md`、`reproducible/EXPERIMENT_DESIGN.md`、`top_tier_desync/EXPERIMENT_PROTOCOL.md` 已并入本节对应段落。

**只想按步骤复现实验**：从下面 **第 0 节** 复制命令即可；设计背景从 **第 1 节** 起阅读。  
**计划跑完全部论文相关仿真**：用 **第 7 节** 的勾选总表与分条命令（含 S01–S04、scalability、去同步、top_tier、后处理）。

---

## 0. 实验复现操作手册（复制即用）

以下命令均在 **仓库根目录**（含 `experiments/`、`simulator_builder.py` 的那一层）执行。将占位路径改为你本机实际路径。

### 0.1 前置条件

- **操作系统**：Linux（与 NS-3 构建环境一致；WSL2 可用）。  
- **NS-3**：已本地编译，存在可执行的 `ns3`（或你使用的构建产物名）。  
- **Python**：建议 3.10+（与仓库依赖兼容即可）。  
- **磁盘与时间**：单次蜂群会在 `experiments/results_*` 下写大量配置与日志；**规模 × 密度档 × 协议 × 种子数** 线性增加总耗时。

### 0.2 进入仓库并设置环境变量（必改 `NS3_BIN`）

```bash
cd /path/to/UAV
export UAV_ROOT="$(pwd)"
export NS3_BIN="/path/to/your/ns3"
export SIMULATOR="${SIMULATOR:-$UAV_ROOT/simulator_builder.py}"
```

可选：两次仿真之间让机器喘口气（与 swarm 默认一致时可不设）：

```bash
export MALLOC_ARENA_MAX=2
```

### 0.3 安装 Python 依赖

```bash
cd "$UAV_ROOT"
python3 -m pip install -r requirements.txt
```

出图（S01 聚合图等）需要 **seaborn**；`requirements.txt` 已包含 `seaborn>=0.13.0`。若只做数值聚合、不出图，缺 seaborn 时脚本仍会写 `aggregated_statistics.json`。

### 0.4 自检：NS-3 与「干跑」命令行

```bash
test -x "$NS3_BIN" && echo "NS3_BIN OK" || echo "请修正 NS3_BIN"
python3 experiments/run_paper_experiment.py --list-kinds
python3 experiments/run_paper_experiment.py \
  --kind baseline \
  --sizes 10 \
  --protocols PMAP_ACK \
  --seeds 20260417 \
  --dry-run
```

`--dry-run` 只打印将要执行的 `swarm_unified_scenario_experiment.py` 命令行，**不启动仿真**。

### 0.5 最小烟测（约 1 个 NS-3 作业：基线）

确认环境无误后再跑真仿真：

```bash
cd "$UAV_ROOT"
python3 experiments/run_paper_experiment.py \
  --kind baseline \
  --sizes 10 \
  --protocols PMAP,PMAP_ACK \
  --seeds 20260417 \
  --motion-modes gauss_markov_3d \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR"
```

成功后，在 `experiments/results_paper_baseline/` 下会出现按场景 tag 划分的子目录，内含 `result.json`（及日志目录，若未 `.gitignore` 忽略）。

### 0.6 Scalability：先小矩阵，再论文默认矩阵

**（A）小矩阵（推荐先跑通）**：单规模、单密度档、单种子、双协议。

```bash
cd "$UAV_ROOT"
python3 experiments/run_paper_experiment.py \
  --kind scalability \
  --sizes 10 \
  --densities low \
  --protocols PMAP,PMAP_ACK \
  --seeds 20260417 \
  --motion-modes gauss_markov_3d \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR"
```

**（B）论文默认矩阵（耗时长）**：不写 `--sizes` / `--seeds` 时使用 `experiment_presets.py` 中 **scalability** 的默认 **10,30,50** 与 **约 30 个种子**；务必显式打开三档密度，否则 swarm 默认不按密度矩阵扫。

```bash
cd "$UAV_ROOT"
python3 experiments/run_paper_experiment.py \
  --kind scalability \
  --densities low,medium,high \
  --protocols PMAP,PMAP_ACK \
  --motion-modes gauss_markov_3d \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR"
```

若需与历史结果同种子子集，可显式传入，例如：

```bash
python3 experiments/run_paper_experiment.py \
  --kind scalability \
  --sizes 10,30,50 \
  --densities low,medium,high \
  --protocols PMAP,PMAP_ACK \
  --seeds 20260417,20260418,20260419 \
  --motion-modes gauss_markov_3d \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR"
```

产物根目录默认为 **`experiments/results_paper_scalability/`**（可用 `--out-root` 改掉）。

### 0.7 边界去同步（`desync_boundary`）

**单臂快测（ACK 边界，一轮调度 + 多轮自恢复由 preset 决定）**：

```bash
cd "$UAV_ROOT"
python3 experiments/run_paper_experiment.py \
  --kind desync_boundary \
  --sizes 10 \
  --protocols PMAP,PMAP_ACK \
  --seeds 20260417 \
  --boundary-profile ack_once \
  --motion-modes task_random \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR"
```

**换臂（M3/M4 边界）**：把 `--boundary-profile m3m4_once`。

**两臂顺序跑 + 对比图**（耗时显著高于单臂；默认输出在仓库内如下路径）：

```bash
cd "$UAV_ROOT"
python3 experiments/run_desync_boundary_suite.py
```

脚本内部会依次写入 **`experiments/results_desync_boundary/ack_once`**、**`.../m3m4_once`**，并调用绘图生成 **`experiments/results_desync_boundary/figures/pmap_vs_pmap_ack_success.png`**。环境变量 **`NS3_BIN`**、**`SIMULATOR`** 与单臂命令相同。

### 0.8 顶会双臂流水线（Top-tier desync）

顺序执行 **ack_once** 与 **m3m4_once** 两臂 swarm、轮次分析、汇总图：

```bash
cd "$UAV_ROOT"
python3 experiments/run_paper_experiment.py --kind top_tier --ns3 "$NS3_BIN" --simulator "$SIMULATOR"
```

等价于直接调用：

```bash
python3 experiments/run_top_tier_desync_experiment.py
```

产物默认在 **`experiments/results_top_tier_desync/`**，并写 `MANIFEST.json`（其中 `design_doc` 指向本 `EXPERIMENTS.md`）。

### 0.9 可复现统计批处理（S01–S04）

在仓库根执行 shell 脚本（内部已 `cd` 到仓库根）。**务必先设置 `NS3_BIN`**（脚本内有默认值，可能不是你的路径）。

```bash
cd "$UAV_ROOT"
export NS3_BIN="$NS3_BIN"
export SIMULATOR="$SIMULATOR"
bash experiments/reproducible/run_s01_main_scalability.sh
bash experiments/reproducible/run_s02_mobility_stress.sh
bash experiments/reproducible/run_s03_channel_stress.sh
bash experiments/reproducible/run_s04_combined_stress.sh
```

S01 脚本在跑完 swarm 后会自动调用 **`aggregate_and_plot.py`**。其它 S02–S04 若需同样聚合，可仿照 S01 在脚本末尾增加对 `aggregate_and_plot.py` 的调用，或手动执行 **0.10**。

自定义输出目录与多种子（示例）：

```bash
export OUT_S01="$UAV_ROOT/experiments/results_repro_s01_custom"
export SEEDS="20260417,20260418,20260419"
bash experiments/reproducible/run_s01_main_scalability.sh
```

### 0.10 对已有结果根目录做聚合与出图

```bash
cd "$UAV_ROOT"
python3 experiments/reproducible/aggregate_and_plot.py \
  --results-root experiments/results_repro_s01 \
  --charts-dir experiments/results_repro_s01/charts
```

将 `--results-root` 换成你实际的 swarm 输出根路径。

### 0.11 如何确认「复现成功」

1. **进程退出码**：上述命令退出时为 `0`。  
2. **目录结构**：对应 `results_*` 下有多层子目录，且存在 **`result.json`**。  
3. **快速查看指标**（示例路径请按你本次 `--out-root` 替换）：

```bash
cd "$UAV_ROOT"
python3 -c "import json,glob; p=glob.glob('experiments/results_paper_scalability/**/result.json', recursive=True); print(len(p), 'result.json'); print(json.load(open(p[0]))['tag'] if p else 'no files')"
```

4. **顶会流水线**：`experiments/results_top_tier_desync/MANIFEST.json` 存在，且各 `arm` 子目录非空。

### 0.12 常见问题

| 现象 | 处理 |
|------|------|
| 找不到 `ns3` | 检查 `NS3_BIN` 是否为**可执行文件**绝对路径。 |
| 规模/种子未按预期 | `run_paper_experiment.py` 对省略项使用 **KINDS 默认值**；缩小矩阵请显式传 `--sizes`、`--seeds`、`--densities`。 |
| Scalability 未扫密度 | 必须传 `--densities low,medium,high`（或子集），否则 swarm 端默认 `0.0` 不按密度矩阵。 |
| 中断后续跑 | `swarm_unified_scenario_experiment.py` 支持 **`--resume`**；S01 脚本已带 `--resume`，可续跑未完成的组合。 |
| 只想验证代码路径 | 多用 `--dry-run`。 |

---

## 1. 快速索引

### 1.1 网络规模与密度（Scalability）

- **目的**：在 Gauss–Markov 3D 机动与 `twc2025_elevation_aware` 信道下，评估 \(N\)、\(\rho\)、协议（PMAP / PMAP_ACK）对端到端认证指标的影响。  
- **入口**：`swarm_unified_scenario_experiment.py`（`--densities low,medium,high` 等）、`run_paper_experiment.py --kind scalability`。  
- **统计与复现**：`reproducible/` 下 S01–S04 脚本与 `aggregate_and_plot.py`（详见 **第 5 节**）。  
- **主要产物**：`results_paper_scalability/`（`swarm_manifest.json`、各 tag 下 `result.json` 与日志）。

### 1.2 去同步与边界恢复（PMAP vs PMAP_ACK）

- **目的**：在受控去同步模板下，对比 PMAP 与 PMAP_ACK（含 D2Z_ACK 路径）的行为与恢复能力。  
- **入口**：  
  - **微观叙事（单机–ZSP、N=1）**：`run_microscopic_desync_experiment.py` → `results_desync_microscopic/`；  
  - **宏观统计（N=10/30）**：`run_top_tier_desync_experiment.py` → `results_top_tier_desync/`；  
  - 边界套件：`run_desync_boundary_suite.py`、`plot_desync_boundary_comparison.py`。  
- **设计细节**：**第 4 节**（含 4.0 叙事与宏观/微观分工）。  
- **主要产物**：`results_top_tier_desync/`。

### 1.3 其它论文向入口（可选）

- `run_paper_experiment.py` 的 `KINDS`（`experiment_presets.py`）仍支持 `baseline`、`desync_attack`、`desync_single_round` 等；与上两类相比为**补充矩阵**，需要时再跑。  
- **后处理**：`reaggregate_results.py`、`generate_paper_figures.py`；主统计图表首选 `reproducible/aggregate_and_plot.py`。

### 1.4 已移除内容（不再维护）

以下类型已从 `experiments/` 删除：**早期学术重跑目录**、**旧统计批处理结果树**、**与 swarm 主线重复的独立脚本**、**过程性审计 Markdown**。若需历史数据，请从备份或 Git 历史中恢复。

---

## 2. 规模与密度（Scalability）设计

### 2.1 实验目标

**核心指标**

- **可扩展性**：协议在不同网络规模下的性能退化趋势。  
- **密度敏感性**：单位面积 UAV 数量对认证成功率的影响。  
- **拓扑动态性**：网络拓扑变化率对协议稳定性的影响。  
- **信道竞争**：高密度场景下 MAC 层竞争对认证延迟的影响。

**学术对标（叙事参考）**

- IEEE TWC 2024/2025 UAV 网络 scalability 基准；ACM MobiHoc FANET mobility；IEEE IoTJ 大规模无人机认证评估框架。

### 2.2 实验维度矩阵

**网络规模**

| 档位 | n_uavs | 用例 |
|------|--------|------|
| small | 10, 30 | 单集群战术小队验证 |
| medium | 50, 100 | 城市监控 / 搜救 |
| large | 200（可选） | 灾害 / 编队展示，视时间成本 |

**网络密度（`density_levels`）**

| 档位 | ρ (UAVs/km²) | 场景叙事 |
|------|--------------|----------|
| low | 1.0 | 农村 / 海上，干扰弱 |
| medium | 10.0 | 城郊监控 |
| high | 50.0 | 演唱会 / 体育场 / 灾难现场 |

面积边长按密度与 N 自适应推导（与 swarm 配置一致）。

**动态拓扑（机动叙事）**

| 模式 | pattern | 拓扑变化率叙事 |
|------|-----------|----------------|
| 集群 | `gauss_markov_3d_clustered` | 低，编队 |
| 汇聚-分散 | `waypoint_mission` | 高，阶段性剧烈变化 |
| 独立随机 | `gauss_markov_3d` | 很高，低相关 α≈0.3 |

### 2.3 信道竞争（设计参考）

- **WiFi**：802.11ah、2 MHz、保守速率；CSMA/CA 参数与队列叙事见实现 `Simulator`。  
- **干扰**：同频 Nakagami-m、隐藏终端等叙事与 **第 3 节** 信道配置对齐。

### 2.4 多 ZSP 部署（叙事）

- **单 ZSP**：覆盖半径约 5 km，适合 N≤50。  
- **多 Cell（scalability 推荐）**：约每 25 架 UAV 一个 ZSP、网格布局、可切换。  
- **分层**：超大规模可选地面 + 空中 ZSP。

### 2.5 关键评估指标（YAML 叙事摘要）

- **延迟随 N**：`avg_auth_latency_ms`，期望次线性或饱和于信道容量。  
- **成功率随 N**：`protocol_correctness_rate`，例如 N≤100 维持高成功率叙事阈值。  
- **密度–延迟曲线**：ρ 增大后期望尾部变差；**冲突率 / 信道占用** 作补充读数。  
- **拓扑变化率**：断链率 / 连通时间占比等。

### 2.6 执行命令示例

矩阵由 `run_paper_experiment.py` / `swarm_unified_scenario_experiment.py` 根据 presets 生成，勿依赖已删除的独立生成器脚本。

```bash
# 小规模快速验证
python3 experiments/run_paper_experiment.py \
  --kind scalability \
  --sizes 10,30 \
  --densities low,medium \
  --protocols PMAP,PMAP_ACK \
  --seeds 20260417

# 中等规模（示例）
python3 experiments/run_paper_experiment.py \
  --kind scalability \
  --sizes 30,50,100 \
  --densities low,medium,high \
  --mobility swarm_cluster,converge_diverge \
  --zsp-mode multi_cell \
  --protocols PMAP,PMAP_ACK \
  --seeds 20260417,20260418,20260419
```

### 2.7 论文图表规划（Scalability）

- **图 1**：N–成功率，PMAP vs PMAP_ACK。  
- **图 2**：N×ρ 热力图。  
- **图 3**：密度分档延迟箱线。  
- **图 4**：机动模式（集群 vs 随机）对会话完成率的影响。

---

## 3. 场景栈：GM3D、WiFi+Nakagami、D2Z 与论文表述

### 3.1 Gauss–Markov 3D

**实现**：`Mobility/mobility.py`，类型 `gauss_markov_3d`。

典型参数（与 IEEE TWC / INFOCOM 叙事一致的量级）：

- `alpha` ≈ 0.8（记忆因子）；`speed_mean` / `speed_std` 约 15±5 m/s；活动区域与高度范围按场景配置；`duration`、`time_step` 与 swarm 一致。

**特性**：速度 / 方向记忆、3D 高度、边界反弹。

### 3.2 WiFi + Nakagami-m

**实现**：`Simulator/simulator_builder.py`。

- 802.11ah 量级速率；`loss_model: nakagami`，近 / 中 / 远场 m 参数分档；与 **主实验 academic profile**（如 `twc2025_elevation_aware`）对齐时以 CLI / profile 为准。

### 3.3 D2Z 单轮与攻击叙事（配置示例）

单轮高效实验常用：`duration` 缩短、`auth_trigger.time_offsets_s`、`attack_model.desync_template`（如 `boundary_ack_once`）、`d2z_ack_timeout_s`、`max_d2z_attempts` 等与 `experiment_presets` / swarm 构建一致。

对比矩阵叙事：

| 实验 | 移动 | 信道 | 攻击 | 目的 |
|------|------|------|------|------|
| baseline | GM3D | profile 内 WiFi | 无 | 基线 |
| ack 边界 | GM3D | 同上 | ACK 抑制 | PMAP_ACK 抗 ACK 叙事 |
| M3/M4 边界 | GM3D | 同上 | M3/M4 丢弃 | 去同步有效性 |

### 3.4 学术标准对照表（摘要）

- **移动**：3D、Gauss–Markov、α 与速度范围与文献常见区间一致。  
- **信道**：802.11ah + Nakagami 分段 m；路径损耗模型以实现的 Friis / TwoRay 组合为准（设计文档曾标注「近似」处以实现为准）。

### 3.5 命令示例（`run_paper_experiment`）

```bash
python3 experiments/run_paper_experiment.py \
  --kind baseline \
  --sizes 10,30 \
  --protocols PMAP,PMAP_ACK \
  --motion-modes gauss_markov_3d \
  --seeds 20260417,20260418,20260419

python3 experiments/run_paper_experiment.py \
  --kind desync_single_round \
  --sizes 10,30 \
  --protocols PMAP,PMAP_ACK \
  --motion-modes gauss_markov_3d \
  --seeds 20260417,20260418,20260419

python3 experiments/run_paper_experiment.py --list-kinds
```

### 3.6 论文表述模板（方法节 / 结果节）

**场景**

> 采用 Gauss–Markov 3D（α≈0.8），UAV 在配置空域内飞行；信道采用 IEEE 802.11ah 与距离相关 Nakagami-m 衰落，模拟 A2G 多径。

**结果（示例句式，需用实测数替换）**

> 在 ACK 边界攻击下，PMAP_ACK 通过单轮认证与超时 / 重试语义达到高成功率，与无 ACK 边的 PMAP 形成对照叙事。

### 3.7 实现锚点（维护者）

| 模块 | 职责 |
|------|------|
| `Mobility/mobility.py` | GM3D |
| `Simulator/simulator_builder.py` | WiFi + 衰落 |
| `experiments/swarm_unified_scenario_experiment.py` | GM3D / 密度等 CLI |
| `experiments/experiment_presets.py` | 论文 kind 默认 |

### 3.8 后续扩展（D2D）

U2U 模式、无 ZSP 等可作为未来工作；配置骨架见历史 D2Z 文档中的 JSON 草图，以实现代码为准。

---

## 4. 边界去同步、双臂流水线与 RLBA

### 4.0 叙事主线（推荐正文写法）：单机–地面站、多轮认证、「中途」插入攻击

**场景对象**：将每条 **UAV ↔ ZSP（地面站）** 的鉴权过程视为 **时间上顺序排列的多轮 D2Z**（`allow_reauth` 下的多次触发）。攻击不建模为「全网持续瘫痪」，而是 **在已有会话流中插入有限次边界动作**。

**「中途」的操作含义（与实现对齐）**

- **`boundary_*_once` + `desync_attack_first_auth_only`**：对每个 UAV，攻击方在 **其首次相关鉴权轮次** 至多拦截 **一次** M3/M4 或 **一次** D2Z_ACK（依臂而定）；对应轮次记为 **受扰轮**；其后轮次在配置为 **边界自恢复**（`--desync-boundary-recovery`）时，为 **干净轮**，用于观察 **自恢复** 与 **轮次分解成功率**。  
- 正文可把 **round index 1** 叙述为「攻击窗口所在轮或紧挨其后的观测轮」，**round ≥2** 叙述为「攻击已结束后的再鉴权 / 干净信道条件下的闭合行为」——具体以日志与 `round_analysis_*.json` 为准，勿与 **`--desync-multi-round` 且无边界限制时的「每轮可反复攻击」** 混用。

**宏观 vs 微观（两层实验）**

| 层级 | 规模 / 脚本 | 论文作用 |
|------|-------------|----------|
| **微观（案例）** | **N=1**，`run_microscopic_desync_experiment.py` 或 `--kind desync_boundary_micro` | 时间轴清晰：单机–ZSP、多轮、受扰轮与恢复轮；适合 **方法图 / 动机图 / 附录轨迹**。 |
| **宏观（统计）** | **N=10,30**（及蜂群实验），`run_top_tier_desync_experiment.py`、`run_desync_boundary_suite.py` | 跨 UAV、多种子的 **配对统计 + Wilson 区间**；支撑 **可扩展性与普适性** 结论。 |

### 4.1 威胁模型（学术叙事）

攻击作用在 **「动态假名 / PID–CRP 更新与下行确认」边界**，而非对两条关键边做无限次同步剥夺。

**模板（代码层）**

| 模板 ID | `intercept_m3_m4_delivery` | `intercept_d2z_ack_send` | `desync_attack_first_auth_only` |
|---------|---------------------------|----------------------------|----------------------------------|
| `boundary_m3m4_once` | 是 | 否 | 是（每 UAV 对 M3/M4 至多丢一次） |
| `boundary_ack_once` | 否 | 是 | 是（每 UAV 对 ACK 至多抑一次；PMAP 无 ACK 边则钩无效） |

**多轮自恢复**：`--desync-boundary-recovery` 在 `build_unified_config` 中为每架 UAV 排多次 D2Z 触发（`allow_reauth: true`），仿真拉长。与 **`--desync-multi-round` 且 `desync_attack_every_round: true`** 的「每轮持续攻击」不同；后者用于压力上界，**勿与边界自恢复混作同一结论**。

**观测**：`desync_experiment_enabled` 为真时，`Common/desync_experiment_hooks.py` 输出 `DESYNC_EXPERIMENT_PID_TRANSITION`，可与 `D2Z_M3_M4_INTERCEPTED` / `D2Z_ACK_SUPPRESSED` 对齐分析。

### 4.2 实验矩阵

**微观（单机–ZSP 叙事主实验）**

- **协议**：PMAP、PMAP_ACK。  
- **规模**：**N=1**（仅一架 UAV 与 ZSP 形成主会话链）。  
- **运动**：`task_random`（与顶会双臂一致，便于与宏观实验对照）。  
- **信道**：`twc2025_elevation_aware`。  
- **两臂**：`ack_once` / `m3m4_once`（与宏观相同语义）。  
- **入口**：`python3 experiments/run_microscopic_desync_experiment.py`（一键：双臂 swarm → `round_curve_analysis` → `plot_top_tier_figures`），或 `run_paper_experiment.py --kind desync_boundary_micro` 单臂调试。

**宏观（统计主文 / 与 S01 并列）**

- **协议**：PMAP、PMAP_ACK。  
- **规模**：N=10、30。  
- **种子**：≥3。  
- **运动**：`task_random`。  
- **信道**：`twc2025_elevation_aware`。  
- **两臂**：同上。  
- **入口**：`run_top_tier_desync_experiment.py`、`run_desync_boundary_suite.py`。

**出图**：微观与宏观均生成 `round_analysis_*.json` 后可用 **`plot_top_tier_figures.py --results-root <对应根目录>`**（已支持任意 N）；套件柱状图仍用 `run_desync_boundary_suite.py` → `plot_desync_boundary_comparison.py`。

### 4.3 预期结论叙事（需实测后写入正文）

- **ACK 臂**：PMAP_ACK 在 **受扰轮** 可能因 ACK 被拦出现超时/重试；**后续干净轮** 应能闭合会话。PMAP 无 ACK 边 → **阴性对照**。微观 N=1 便于用 **单条会话时间线** 展示；宏观 N=10/30 给出 **种群均值 ± 不确定度**。  
- **M3/M4 臂**：两协议在受扰轮均可受损；差异来自重试与状态机。微观图强调 **「第几轮发生了什么」**；宏观图强调 **统计上是否恢复**。

### 4.4 RLBA_UAV 对称实验？

**可以单独设计 RLBA 实验，但不建议与 PMAP/PMAP_ACK 共用主表不加脚注。**

- `intercept_d2z_ack_send` 在 RLBA 上映射为抑制 SUCCESS 类下行（见 `RLBAZSP` 注释），与 PMAP_ACK 的 D2Z_ACK–PID 切换是**不同消息与状态机**。  
- 若做附录：单独小节「RLBA 下行完成包可达性」，仍可用 `boundary_ack_once` 语义（拦 SUCCESS），指标用完成率 / 超时；或定义 RLBA 专用模板（未来工作）。

### 4.5 命令速查

**微观一键流水线（N=1，双臂 + 轮次图）**

```bash
cd /home/zhang/UAV
python3 experiments/run_microscopic_desync_experiment.py
```

**微观单臂（调参）**

```bash
python3 experiments/run_paper_experiment.py --kind desync_boundary_micro \
  --boundary-profile ack_once \
  --out-root experiments/results_desync_microscopic/ack_once \
  --ns3 "$NS3_BIN" --simulator "$SIMULATOR"
```

**宏观蜂群（与历史命令一致）**

```bash
python3 experiments/swarm_unified_scenario_experiment.py \
  --sizes 10,30 --protocols PMAP,PMAP_ACK --motion-modes task_random \
  --seeds 20260417,20260418,20260419 \
  --desync-boundary-recovery --desync-boundary-profile ack_once \
  --out-root experiments/results_desync_boundary/ack_once \
  --academic-profile twc2025_elevation_aware \
  --simulator /home/zhang/UAV/simulator_builder.py

python3 experiments/run_desync_boundary_suite.py
python3 experiments/run_top_tier_desync_experiment.py
```

（将 `--simulator` / `NS3_BIN` 换为本机路径。）

---

## 5. 可复现统计实验（S01–S04）

在仓库根目录执行（或 `export UAV_ROOT=/path/to/UAV` 后 `cd "$UAV_ROOT"`）。

### 5.0 设计审计（与第 4 节去同步的关系）

| 维度 | S01–S04（本仓库脚本） | 去同步（micro / top_tier / boundary suite） |
|------|------------------------|---------------------------------------------|
| **机动模型** | 一律 **`gauss_markov_3d`**；应力由 `--gm3d-stress` 分档（见 `swarm_unified_scenario_experiment.py` 中 `GM3D_STRESS_PRESETS`：名义约 **5±5 m/s**，aggressive 约 **12±7 m/s**）。 | 默认 **`task_random`**（航点 + 随机化，`max_speed_task_random_mps=22`），**与 GM3D 速度分布不同**。 |
| **设计意图** | 因子实验：规模×密度、纯机动应力、纯信道应力、组合应力；**控制叙事变量**。 | 安全叙事：**高动态任务驱动**下边界攻击 + 多轮恢复；与 S01 主表 **并列呈现**，勿混为同一「速度条件」下的 A/B。 |
| **信道** | S01 无 RSSI/burst；S03/S04 打开。 | `twc2025_elevation_aware`，与 S01 同 profile。 |
| **种子** | `run_s01` 默认 **12** 个种子（s20260417-s20260428）；`run_s02` 默认 **8** 个种子（s20260417-s20260424）；`run_s03` 默认 **8** 个种子（s20260417-s20260424）；`run_s04` 默认 **12** 个种子（s20260417-s20260428）（均可被 `SEEDS` 覆盖）。 | 顶会/微观流水线默认 **3** 个种子；需要与 S01 同分布时可显式传 `--seeds`。 |
| **论文写法建议** | 正文「可扩展性 / 应力」小节引用 S01–S04。 | 「威胁与恢复」小节引用去同步；**一句脚注**说明机动模型与主统计实验不同、为何仍有效（攻击窗口在协议边界，与绝对速度标量弱相关或强调 task_random 更激进）。 |
| **可选对齐实验**（附录） | 若审稿人要求「同 GM3D nominal 下去同步」：可用 `swarm_unified_scenario_experiment.py` 自行组合 `--motion-modes gauss_markov_3d --gm3d-stress nominal --desync-boundary-recovery ...`（与当前预设 `task_random` 结果不可直接数值对比）。 |

### 5.1 环境变量（可选）

- `NS3_BIN`：ns3 可执行文件。  
- `SIMULATOR`：`simulator_builder.py` 路径。  
- `SEEDS`：逗号分隔整数，**覆盖脚本内默认列表**（20–30 次重复时用）。  
- `OUT_S01` … `OUT_S04`：各研究输出根目录（见各 `.sh` 内默认值）。

### 5.2 因子设计（与 Scalability 维度对齐）

| 编号 | 研究问题 | 操纵因子 | 固定 / 对照 | 实际执行范围 |
|------|----------|----------|-------------|-------------|
| **S01** 主可扩展性 | N、ρ、协议下成功率与延迟 | N∈{10,30,50}，ρ∈{1,10,50}，PMAP / PMAP_ACK | `twc2025_elevation_aware`，GM3D `nominal`，无 RSSI/burst | 规模：10, 30, 50；密度：1, 10, 50；协议：PMAP, PMAP_ACK；种子：12个 |
| **S02** 机动应力 | 高动态是否加剧超时 / 失败 | `--gm3d-stress` conservative / nominal / aggressive | 信道同 S01，ρ=low | 规模：10, 30；密度：1；协议：PMAP, PMAP_ACK；应力：conservative, nominal, aggressive；种子：8个 |
| **S03** 信道应力 | 边缘链路 + 突发差信道 | `--rssi-loss-enabled` + `--burst-loss-enabled` | GM3D `nominal`，ρ=low | 规模：10, 30, 50；密度：1；协议：PMAP, PMAP_ACK；信道：RSSI+burst；种子：8个 |
| **S04** 组合应力 | 机动 + 信道同时恶化 | aggressive + RSSI + burst | 子集 N∈{10,30}，ρ=low | 规模：10, 30；密度：1；协议：PMAP, PMAP_ACK；条件：aggressive+RSSI+burst；种子：12个 |

### 5.3 统计口径

- **单元**：一次 `(motion, N, ρ, protocol, gm3d_stress, channel_flags)` 的 NS3 运行。  
- **重复**：不同 `--seeds`（S01/S04 默认 **12** 个种子，S02/S03 默认 **8** 个种子，可用 `SEEDS` 扩展）。  
- **图表**：对 `success_rate_percent`（及可选 `avg_duration`）跨种子算 **t 分布 95% CI**（`aggregate_and_plot.py`）；单种子时误差棒为 0。

### 5.4 与实现对齐

- 场景：`swarm_unified_scenario_experiment.py`。  
- 统计：`analysis/statistical_utils.py`。  
- 绘图：`analysis/chart_generator.py`。

### 5.5 脚本一览与聚合

| 脚本 | 内容 | 实际输出目录结构 |
|------|------|------------------|
| `reproducible/run_s01_main_scalability.sh` | S01：N×ρ×协议×多种子 | `gauss_markov_3d_n<size>_d<density>_<protocol>_s<seed>` |
| `reproducible/run_s02_mobility_stress.sh` | S02：三档 GM3D 应力 | `gauss_markov_3d_n<size>_d<density>_<protocol>_s<seed>_gm<stress>` |
| `reproducible/run_s03_channel_stress.sh` | S03：RSSI + burst | `gauss_markov_3d_n<size>_d<density>_<protocol>_s<seed>_chRB` |
| `reproducible/run_s04_combined_stress.sh` | S04：组合应力（子集） | `gauss_markov_3d_n<size>_d<density>_<protocol>_s<seed>_gmaggressive_chRB` |

```bash
# S01 聚合
python3 experiments/reproducible/aggregate_and_plot.py \
  --results-root experiments/results_repro_s01 \
  --charts-dir experiments/results_repro_s01/charts

# S02 聚合
python3 experiments/reproducible/aggregate_and_plot.py \
  --results-root experiments/results_repro_s02 \
  --charts-dir experiments/results_repro_s02/charts \
  --filter-density 1

# S03 聚合
python3 experiments/reproducible/aggregate_and_plot.py \
  --results-root experiments/results_repro_s03 \
  --charts-dir experiments/results_repro_s03/charts \
  --filter-density 1

# S04 聚合
python3 experiments/reproducible/aggregate_and_plot.py \
  --results-root experiments/results_repro_s04 \
  --charts-dir experiments/results_repro_s04/charts \
  --filter-density 1 \
  --filter-gm aggressive
```

### 5.6 依赖

聚合脚本在缺少 **seaborn** 时仍写出 `aggregated_statistics.json`，但跳过出图：`pip install seaborn`。

---

## 6. Top-tier desync protocol (English, preregistered-style)

*Frozen narrative for reviewers; code entrypoint: `run_top_tier_desync_experiment.py`.*

### Objective

Quantify **paired** (same seeds / mobility / schedule) **PMAP vs PMAP_ACK** resilience under **limited, boundary-focused desynchronization** with **multi-round reauth**, emphasizing **self-recovery** rather than perpetual channel starvation.

**Narrative (recommended paper text)**: treat each **UAV–ZSP** authentication stream as **time-ordered D2Z rounds**; the attacker inserts **at most one bounded action per UAV** on the attacked edge (`boundary_*_once`) during the **early authenticated rounds**, after which **clean rounds** observe recovery. **Microscopic runs** (`N=1`, `run_microscopic_desync_experiment.py`) explain the timeline; **macroscopic runs** (`N∈{10,30}`, `run_top_tier_desync_experiment.py`) provide fleet-level statistics.

### Design choices

| Choice | Rationale |
|--------|-----------|
| **Paired comparison** | Same `motion_mode`, `seed`, `N`, trigger schedule, academic channel profile, and attack arm across protocols → reduces mobility variance. |
| **Two attack arms** | **ACK-only** (`boundary_ack_once`) stresses **confirmation boundary** (meaningful for PMAP_ACK; PMAP is a **negative control** on that arm). **M3/M4-only** (`boundary_m3m4_once`) stresses **uplink update boundary** → **symmetric** stress for both protocols. |
| **Limited interference** | `desync_attack_first_auth_only=true` + **no** `desync_attack_every_round` → attacks are **bounded**, not per-round starvation. |
| **Multi-round schedule** | `--desync-boundary-recovery` → three scheduled D2Z attempts per UAV with `allow_reauth=true` → enables **round-resolved** outcome curves. |
| **Primary readout** | **Per-UAV authentication round** (1…R) **instantaneous success rate** (fleet mean ± 95% Wilson or bootstrap across seeds × UAVs). |
| **Secondary readouts** | End-of-sim `success_rate_percent`, `protocol_success_rate`, `timeout_sessions` from `result.json` analyzer. |
| **Re-registration** | **Out of scope** for this preregistered run; reserved for appendix if added later. |

### Hypotheses (testable, descriptive + CIs)

1. **H1 (ACK arm)**: Under `boundary_ack_once`, **PMAP_ACK** shows **non-decreasing** mean per-round success after round 1; round-2/3 mean **>** round-1 mean **or** equal within CI. **PMAP** shows **no** extra degradation vs no-attack baseline on this arm.  
2. **H2 (M3/M4 arm)**: Under `boundary_m3m4_once`, both may dip early; **PMAP_ACK** does **not underperform** PMAP on **post-attack rounds** beyond a pre-specified margin (report CI).

### Fixed parameters (this protocol version)

- `motion_mode`: `task_random`  
- `sizes`: `10,30`  
- `protocols`: `PMAP,PMAP_ACK`  
- `seeds`: `20260417,20260418,20260419`  
- `academic_profile`: `twc2025_elevation_aware`  
- `arms`: `ack_once`, `m3m4_once` → `boundary_ack_once`, `boundary_m3m4_once`  
- `boundary_recovery`: enabled  

### Outputs

- Raw runs: `experiments/results_top_tier_desync/<arm>/…`  
- Manifest + round stats + figures: produced by `run_top_tier_desync_experiment.py`  

**Protocol file version**: 1.0 (2026-04-18) — **content location**: this section of `EXPERIMENTS.md` (replaces standalone `EXPERIMENT_PROTOCOL.md`).

---

## 7. 实验跑数完整清单（含执行命令）

下列清单面向 **「仿真平台论文 + PMAP_ACK 作为案例优化」**：覆盖可复现统计（S01–S04）、主文 scalability、多种去同步形态、顶会双臂流水线、三协议对照、聚合与出图。**非「最小集」**：可按时间与算力分阶段执行；建议顺序见 **7.0**。

**通用前置**（每条命令前执行一次即可）：

```bash
cd /path/to/UAV
export UAV_ROOT="$(pwd)"
export NS3_BIN="/path/to/ns3"
export SIMULATOR="${SIMULATOR:-$UAV_ROOT/simulator_builder.py}"
export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"
```

下文 **`$UAV_ROOT`** 表示仓库根；示例中 Python 路径写为 `python3`，若在根目录也可写 `python3 "$UAV_ROOT/experiments/..."`。

### 7.0 建议执行顺序（调度用）

| 阶段 | 目的 |
|------|------|
| **A** | 清单 **7.1**（基线烟测）→ 确认 NS-3 与依赖无误。 |
| **B** | **7.2** `test_gm3d_runtime.py`（可选但推荐，改机动相关代码后必跑）。 |
| **C** | **7.4** S01→S02→S03→S04（可复现统计主块；S01 最长）。 |
| **D** | **7.3** 论文 scalability 全矩阵（可与 C 并行不同机器）。 |
| **E** | **7.5** 去同步与边界类（含 **微观 N=1**、top_tier、boundary suite、其它 kind）。 |
| **F** | **7.6** 三协议 RLBA 对照（可选）。 |
| **G** | **7.7** 各结果树 `reaggregate` / `aggregate_and_plot` 补漏。 |
| **H** | **7.8** `generate_paper_figures.py` 汇总出图。 |

---

### 7.1 基线烟测（无攻击）

| ID | 说明 | 默认产物目录 |
|----|------|----------------|
| B0 | 干跑只看命令行 | — |
| B1 | 最小真跑：N=10、单种子 | `experiments/results_paper_baseline/` |

```bash
cd "$UAV_ROOT"
python3 experiments/run_paper_experiment.py \
  --kind baseline \
  --sizes 10 \
  --protocols PMAP,PMAP_ACK \
  --seeds 20260417 \
  --motion-modes gauss_markov_3d \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR" \
  --dry-run

python3 experiments/run_paper_experiment.py \
  --kind baseline \
  --sizes 10 \
  --protocols PMAP,PMAP_ACK \
  --seeds 20260417 \
  --motion-modes gauss_markov_3d \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR"
```

**扩大基线**（与论文表格一致时可加规模/多种子，自行改 `--sizes`、`--seeds`）：

```bash
python3 experiments/run_paper_experiment.py \
  --kind baseline \
  --sizes 10,30,50 \
  --protocols PMAP,PMAP_ACK \
  --motion-modes gauss_markov_3d \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR"
```

（不写 `--seeds` 时使用 preset 内默认长种子串，耗时会显著增加。）

---

### 7.2 机动集成回归（配置与 GM3D）

| ID | 脚本 | 说明 |
|----|------|------|
| T1 | `experiments/test_gm3d_runtime.py` | 不跑 NS-3 全仿真时仍验证配置生成等 |

```bash
cd "$UAV_ROOT"
python3 experiments/test_gm3d_runtime.py
```

---

### 7.3 论文主表：Scalability（规模 × 密度 × 协议 × 种子）

| ID | 说明 | 默认产物目录 |
|----|------|----------------|
| SCL-1 | **小矩阵**（联调） | `experiments/results_paper_scalability/` |
| SCL-2 | **全矩阵**：10/30/50 × low/medium/high × 双协议 × 默认长种子 | 同上 |
| SCL-3 | **全矩阵 + 显式短种子**（控制总时长） | 同上 |

```bash
# SCL-1 小矩阵
cd "$UAV_ROOT"
python3 experiments/run_paper_experiment.py \
  --kind scalability \
  --sizes 10 \
  --densities low \
  --protocols PMAP,PMAP_ACK \
  --seeds 20260417 \
  --motion-modes gauss_markov_3d \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR"

# SCL-2 全矩阵（preset 默认 seeds，非常耗时）
python3 experiments/run_paper_experiment.py \
  --kind scalability \
  --densities low,medium,high \
  --protocols PMAP,PMAP_ACK \
  --motion-modes gauss_markov_3d \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR"

# SCL-3 全矩阵 + 指定种子（示例 9 个）
python3 experiments/run_paper_experiment.py \
  --kind scalability \
  --sizes 10,30,50 \
  --densities low,medium,high \
  --protocols PMAP,PMAP_ACK \
  --seeds 20260417,20260418,20260419,20260420,20260421,20260422,20260423,20260424,20260425 \
  --motion-modes gauss_markov_3d \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR"
```

**Scalability 跑完后的聚合（示例）**：

```bash
cd "$UAV_ROOT"
python3 experiments/reaggregate_results.py \
  --root experiments/results_paper_scalability \
  --out-json experiments/results_paper_scalability/statistics_summary_reaggregated.json \
  --out-md experiments/results_paper_scalability/statistics_summary_reaggregated.md
```

---

### 7.4 可复现统计批处理 S01–S04

| ID | 脚本 | 默认输出根 | 环境变量覆盖 |
|----|------|------------|----------------|
| R01 | `reproducible/run_s01_main_scalability.sh` | `experiments/results_repro_s01` | `OUT_S01`, `SEEDS`, `NS3_BIN`, `SIMULATOR` |
| R02 | `reproducible/run_s02_mobility_stress.sh` | `experiments/results_repro_s02` | `OUT_S02`, `SEEDS`, … |
| R03 | `reproducible/run_s03_channel_stress.sh` | `experiments/results_repro_s03` | `OUT_S03`, `SEEDS`, … |
| R04 | `reproducible/run_s04_combined_stress.sh` | `experiments/results_repro_s04` | `OUT_S04`, `SEEDS`, … |

```bash
cd "$UAV_ROOT"
export NS3_BIN="$NS3_BIN"
export SIMULATOR="$SIMULATOR"
bash experiments/reproducible/run_s01_main_scalability.sh
bash experiments/reproducible/run_s02_mobility_stress.sh
bash experiments/reproducible/run_s03_channel_stress.sh
bash experiments/reproducible/run_s04_combined_stress.sh
```

**自定义输出与种子（示例）**：

```bash
export OUT_S01="$UAV_ROOT/experiments/results_repro_s01_full"
export SEEDS="20260417,20260418,20260419,20260420,20260421"
bash experiments/reproducible/run_s01_main_scalability.sh
```

**仅对某一 S0x 结果补聚合/出图**（脚本未自动调用时）：

```bash
python3 experiments/reproducible/aggregate_and_plot.py \
  --results-root experiments/results_repro_s02 \
  --charts-dir experiments/results_repro_s02/charts \
  --filter-density 1
```

（S02/S03/S04 与仓库脚本一致时可保留 `--filter-density 1`；S04 示例中带 `--filter-gm aggressive` 见脚本内命令。）

---

### 7.5 去同步与安全应力（`run_paper_experiment` kinds）

以下 **`--ns3` / `--simulator` 均建议显式附上**（与第 0 节一致）。**不写 `--seeds` 时使用 preset 中长种子列表**，请预估机时。

| ID | `--kind` | 标题摘要 | 默认 `experiments/` 下产物根 |
|----|-----------|----------|------------------------------|
| D1 | `desync_attack` | 组合去同步（M3/M4 + ACK），单轮默认可攻击 | `results_paper_desync_attack/` |
| D2 | `desync_multiround` | 激进多轮、每轮可攻击 | `results_paper_desync_multiround/` |
| D3 | `desync_single_round` | 单轮 M3/M4 边界 | `results_paper_desync_single_round/` |
| D4 | `desync_ack_single_round` | 单轮 ACK 边界 | `results_paper_desync_ack_single_round/` |
| D5 | `desync_boundary` | 边界 + 多轮自恢复；需 `--boundary-profile` | `results_paper_desync_boundary/`（建议配合 `--out-root` 分臂） |
| D5μ | `desync_boundary_micro` / `run_microscopic_desync_experiment.py` | **N=1** 微观叙事：单机–ZSP 多轮 + 中途边界攻击 | `results_desync_microscopic/` |

```bash
cd "$UAV_ROOT"

python3 experiments/run_paper_experiment.py --kind desync_attack \
  --ns3 "$NS3_BIN" --simulator "$SIMULATOR"

python3 experiments/run_paper_experiment.py --kind desync_multiround \
  --ns3 "$NS3_BIN" --simulator "$SIMULATOR"

python3 experiments/run_paper_experiment.py --kind desync_single_round \
  --ns3 "$NS3_BIN" --simulator "$SIMULATOR"

python3 experiments/run_paper_experiment.py --kind desync_ack_single_round \
  --ns3 "$NS3_BIN" --simulator "$SIMULATOR"

# D5：分臂输出（推荐，避免两次写入同一根目录混淆）
python3 experiments/run_paper_experiment.py --kind desync_boundary \
  --boundary-profile ack_once \
  --out-root experiments/results_paper_desync_boundary/ack_once \
  --motion-modes task_random \
  --ns3 "$NS3_BIN" --simulator "$SIMULATOR"

python3 experiments/run_paper_experiment.py --kind desync_boundary \
  --boundary-profile m3m4_once \
  --out-root experiments/results_paper_desync_boundary/m3m4_once \
  --motion-modes task_random \
  --ns3 "$NS3_BIN" --simulator "$SIMULATOR"
```

#### 7.5.1 双臂边界套件 + 柱状图（与论文 fig3 叙事衔接）

| ID | 脚本 | 产物 |
|----|------|------|
| DS | `run_desync_boundary_suite.py` | `results_desync_boundary/{ack_once,m3m4_once}/`、`figures/pmap_vs_pmap_ack_success.png` |

```bash
cd "$UAV_ROOT"
python3 experiments/run_desync_boundary_suite.py
```

（内部已调用 `plot_desync_boundary_comparison.py`；若仅重绘图可单独运行该 plot 脚本并传 `--groups`，参数以脚本 `--help` 为准。）

#### 7.5.2 微观去同步（N=1，双臂 + 轮次图）

| ID | 脚本 | 产物 |
|----|------|------|
| DM | `run_microscopic_desync_experiment.py` | `results_desync_microscopic/{ack_once,m3m4_once}/`、`round_analysis_*.json`、`figures/` |

```bash
cd "$UAV_ROOT"
python3 experiments/run_microscopic_desync_experiment.py
```

#### 7.5.3 顶会双臂流水线（轮次分析 + 平台 manifest，N=10/30）

| ID | 脚本 | 产物 |
|----|------|------|
| TT | `run_top_tier_desync_experiment.py` 或 `run_paper_experiment.py --kind top_tier` | `results_top_tier_desync/`、`MANIFEST.json`、`round_analysis_*.json` |

```bash
cd "$UAV_ROOT"
python3 experiments/run_paper_experiment.py \
  --kind top_tier \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR"
```

---

### 7.6 可选：三协议对照（PMAP / PMAP_ACK / RLBA_UAV）

平台 CLI 支持 `--protocols PMAP,PMAP_ACK,RLBA_UAV`。可与 **S01 同矩阵** 另起输出目录，便于与双协议结果并列（**机时约为 1.5×**）。

```bash
cd "$UAV_ROOT"
mkdir -p experiments/results_repro_s01_triple
python3 experiments/swarm_unified_scenario_experiment.py \
  --sizes 10,30,50 \
  --protocols PMAP,PMAP_ACK,RLBA_UAV \
  --motion-modes gauss_markov_3d \
  --seeds "${SEEDS:-20260417,20260418,20260419}" \
  --densities low,medium,high \
  --out-root experiments/results_repro_s01_triple \
  --between-sleep 2.0 \
  --academic-profile twc2025_elevation_aware \
  --gm3d-stress nominal \
  --ns3 "$NS3_BIN" \
  --simulator "$SIMULATOR" \
  --resume

python3 experiments/reproducible/aggregate_and_plot.py \
  --results-root experiments/results_repro_s01_triple \
  --charts-dir experiments/results_repro_s01_triple/charts
```

（去同步类实验若以 **RLBA 叙事** 单独设计，参见本文第 4 节 RLBA 讨论；**勿与 PMAP 威胁模板混表** 除非脚注说明语义映射。）

---

### 7.7 后处理：聚合、Markdown 汇总、论文章节图

| ID | 脚本 | 用途 |
|----|------|------|
| P1 | `reaggregate_results.py` | 任意含 `result.json` 的结果树 → `statistics_summary_reaggregated.{json,md}` |
| P2 | `reproducible/aggregate_and_plot.py` | S0x 风格目录 → `aggregated_statistics.json` + `charts/` |
| P3 | `generate_paper_figures.py` | 读 **固定路径** 下 `results_top_tier_desync` 等 → `paper_figures/` |

```bash
cd "$UAV_ROOT"

# P1：对任一结果根（示例：S03）
python3 experiments/reaggregate_results.py \
  --root experiments/results_repro_s03 \
  --out-json experiments/results_repro_s03/statistics_summary_reaggregated.json \
  --out-md experiments/results_repro_s03/statistics_summary_reaggregated.md

# P3：论文综合图（依赖仓库内已有 results_top_tier_desync 等路径；见脚本源码）
python3 experiments/generate_paper_figures.py \
  --out-dir experiments/paper_figures
```

若需让 `generate_paper_figures.py` 额外吃到 **scalability 的 reaggregate 文件**，可将 `statistics_summary_reaggregated.json` 放到脚本当前硬编码查找路径，或后续改脚本增加 `--roots`（当前版本以源码为准）。

---

### 7.8 清单总表（勾选用）

| ☐ | ID | 执行入口 |
|---|-----|----------|
| ☐ | B0/B1 | `run_paper_experiment.py --kind baseline` |
| ☐ | T1 | `test_gm3d_runtime.py` |
| ☐ | SCL-1/2/3 | `run_paper_experiment.py --kind scalability` |
| ☐ | R01–R04 | `reproducible/run_s01..s04_*.sh` |
| ☐ | D1–D5 | `run_paper_experiment.py` 各 `desync_*` / `desync_boundary` |
| ☐ | DS | `run_desync_boundary_suite.py` |
| ☐ | DM | `run_microscopic_desync_experiment.py` |
| ☐ | TT | `run_paper_experiment.py --kind top_tier` |
| ☐ | RLBA | 7.6 节 `swarm_unified_scenario_experiment.py` 三协议 |
| ☐ | P1–P3 | `reaggregate_results.py` / `aggregate_and_plot.py` / `generate_paper_figures.py` |

---

### 7.9 备注

- **`--resume`**：长矩阵务必加上（`swarm_unified_scenario_experiment.py`），S01–S04 脚本已内置。  
- **`--densities`**：scalability 与 S01 类实验必须按需求显式传入，否则默认不按三档 ρ 扫描。  
- **机时**：SCL-2、D1–D2、TT 与 **三协议 S01** 为最重档位；可用 **缩短 `--seeds`**、**缩小 `--sizes`** 先做中间检查点，再跑全量。
