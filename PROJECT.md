以下是完整的项目描述文档内容：

---

# UAV-ZSP 无人机网络安全认证项目完整说明

## 1. 项目概述

本项目是一个基于 NS-3 网络模拟器的无人机（UAV）与零安全平台（ZSP）之间轻量级认证协议的研究与验证框架。项目核心关注**去同步攻击（Desynchronization Attack）**对动态假名认证系统的影响，以及相应的防御机制设计。

### 1.1 核心研究问题

1. **去同步攻击有效性**：攻击者能否通过拦截关键认证消息使无人机与ZSP之间的认证状态不一致？
2. **协议自恢复能力**：遭受攻击后，协议能否自动恢复正常认证流程？
3. **攻击目标特异性**：去同步攻击是否只对动态假名系统有效，而对静态认证无效？

### 1.2 三大核心结论

通过实验验证得到以下三个关键结论：

1. **去同步攻击有效**：PMAP协议（静态假名）在遭受M3/M4拦截攻击后无法恢复，认证完全失败
2. **PMAP_ACK自恢复机制有效**：PMAP_ACK协议（带ACK确认的动态假名）在持续10轮M3/M4攻击后仍能恢复后续认证
3. **攻击针对动态假名系统**：RLBA_UAV协议（匿名认证）对去同步攻击免疫，证明攻击目标是动态假名机制

---

## 2. 核心协议架构

### 2.1 实体定义

- **UAV（无人机）**：配备物理不可克隆函数（PUF）的移动节点
- **ZSP（Zero Security Platform）**：地面基站，负责无人机身份验证和密钥管理
- **协议消息**：基于挑战-响应机制的四步握手（M1-M4）

### 2.2 三大认证协议

#### 2.2.1 PMAP（静态假名映射协议）

- **核心机制**：使用静态PID（Pseudo-IDentifier）映射真实身份
- **特点**：
  - PID在认证过程中保持不变
  - 遭受M3/M4拦截后，UAV和ZSP的PID状态可能不一致
  - **无自恢复能力**：一旦去同步，后续认证完全失败

```python
# 关键代码位置: Entity/ZSP/PMAPZSP.py
class PMAP_ZSP(BaseZSP):
    def __init__(self, ..., d2z_ack_mode: bool = False):
        # d2z_ack_mode=False 时为标准PMAP
        self.protocol_name = "PMAP_ACK" if d2z_ack_mode else "PMAP"
```

#### 2.2.2 PMAP_ACK（带ACK的动态假名协议）

- **核心创新**：引入ACK确认机制和dual-PID过渡窗口
- **特点**：
  - 每次成功认证后更新PID
  - **过渡窗口**：在新PID生效前保留旧PID的验证能力
  - **自恢复机制**：通过ACK确认防止状态不一致

```python
# 关键机制: dual-PID transition window
# old_pid -> {new_pid, new_crp, challenge, response, session_key, expires_at}
self._ack_pending_transition = {}

# 攻击恢复逻辑
# 1. M3/M4拦截：UAV收不到M4，但ZSP已更新PID
# 2. 过渡窗口允许UAV用旧PID重新发起认证
# 3. ACK确认确保双方状态同步
```

#### 2.2.3 RLBA_UAV（匿名认证协议）

- **核心机制**：基于环签名的匿名批认证
- **特点**：
  - 不使用PID映射，采用匿名凭证
  - **免疫去同步攻击**：攻击者无法通过拦截消息破坏认证状态
  - 用于证明攻击目标是动态假名机制

---

## 3. 去同步攻击模型

### 3.1 攻击类型

#### 3.1.1 M3/M4拦截攻击（上行攻击）

- **目标**：拦截并丢弃UAV发送的M3消息或ZSP回复的M4消息
- **影响**：
  - PMAP：ZSP已更新认证状态，UAV未收到确认 → 去同步
  - PMAP_ACK：过渡窗口允许恢复

#### 3.1.2 ACK抑制攻击（下行攻击）

- **目标**：拦截D2Z_ACK确认消息
- **影响**：
  - 仅影响PMAP_ACK（PMAP无ACK机制）
  - PMAP_ACK可通过超时重传恢复

### 3.2 攻击窗口配置

```python
# 攻击参数配置（experiment_presets.py）
desync_attack_min_completed_sessions = 10  # 第10轮开始攻击
desync_attack_max_completed_sessions = 20  # 第20轮停止攻击
# 攻击窗口：连续10轮（第10-20轮）
```

---

## 4. 实验设计体系

### 4.1 实验架构

```
实验入口 → Swarm调度 → NS-3仿真 → 日志收集 → 数据分析 → 图表生成
```

### 4.2 关键实验脚本

| 脚本 | 功能 | 输出 |
|------|------|------|
| `run_microscopic_desync_experiment.py` | 微观三臂实验（叙事图） | Fig1, Fig2, Fig3 |
| `run_paper_experiment.py` | 通用实验入口 | 按kind执行 |
| `swarm_unified_scenario_experiment.py` | 蜂群调度核心 | 多进程并行仿真 |
| `round_curve_analysis.py` | 轮次数据分析 | round_analysis_*.json |
| `plot_top_tier_figures.py` | 图表生成 | PDF/PNG图表 |

### 4.3 三臂微观实验（核心验证）

#### Arm 1: ack_once（持续ACK攻击）

- **配置**：10轮持续ACK抑制攻击
- **协议**：仅PMAP_ACK
- **目的**：验证PMAP_ACK面对持续ACK攻击的恢复能力
- **输出**：Fig 1

#### Arm 2: m3m4_once（单轮M3/M4攻击）

- **配置**：单轮M3/M4拦截
- **协议**：PMAP + PMAP_ACK（+可选RLBA_UAV）
- **目的**：对比两种协议在单轮攻击后的表现差异
- **输出**：Fig 3

#### Arm 3: m3m4_sustained（持续M3/M4攻击）

- **配置**：10轮持续M3/M4拦截
- **协议**：PMAP_ACK
- **目的**：验证PMAP_ACK面对持续上行攻击的恢复能力
- **输出**：Fig 2

### 4.4 图表说明

#### Fig 1: PMAP_ACK under sustained ACK suppression

- **X轴**：认证轮次（120轮）
- **Y轴**：累积成功认证次数
- **攻击标记**：第10-20轮（红色端点+线段）
- **预期结果**：攻击期间成功率下降，攻击结束后恢复上升趋势

#### Fig 2: PMAP_ACK under sustained M3/M4 interception

- **X轴**：认证轮次（120轮）
- **Y轴**：累积成功认证次数
- **攻击标记**：第10-20轮
- **预期结果**：攻击期间受影响，但攻击结束后快速恢复

#### Fig 3: PMAP vs PMAP_ACK under single M3/M4 interception

- **X轴**：认证轮次
- **Y轴**：累积成功认证次数
- **攻击标记**：第2轮（单轮攻击）
- **预期结果**：
  - PMAP：攻击后曲线平坦（无法恢复）
  - PMAP_ACK：攻击后曲线继续上升（成功恢复）
  - RLBA_UAV（如有）：曲线正常上升（免疫攻击）

---

## 5. 代码组织结构

```
UAV/
├── experiments/                    # 实验脚本目录
│   ├── experiment_presets.py       # 实验配置预设
│   ├── run_microscopic_desync_experiment.py  # 微观三臂实验
│   ├── run_paper_experiment.py     # 通用实验入口
│   ├── swarm_unified_scenario_experiment.py   # 蜂群调度
│   ├── top_tier_desync/            # 去同步专项分析
│   │   ├── round_curve_analysis.py # 轮次数据分析
│   │   └── plot_top_tier_figures.py # 叙事图生成（仅Fig1-3）
│   ├── results_desync_microscopic/ # 实验结果
│   │   ├── round_analysis_*.json   # 分析数据
│   │   └── figures/                # 输出图表
│   └── EXPERIMENTS.md              # 完整实验文档
├── Entity/                         # 网络实体
│   ├── UAV/                        # 无人机实现
│   └── ZSP/                        # 零安全平台
│       ├── BaseZSP.py              # ZSP基类
│       ├── PMAPZSP.py              # PMAP/PMAP_ACK协议（核心）
│       └── RLBAZSP.py              # RLBA匿名协议
├── Protocol/                       # 协议定义
│   ├── PMAP/                       # PMAP协议消息格式
│   └── RLBA/                       # RLBA协议消息格式
├── Common/                         # 公共模块
│   ├── attack_model.py             # 攻击模型定义
│   └── desync_attack_template.py   # 去同步攻击模板
├── Backend/                        # 后端分析
│   ├── core/                       # 日志解析核心
│   └── analysis/                   # 协议分析器
├── Mobility/                       # 移动模型
│   └── gauss_markov_3d_model.py  # 3D高斯-马尔科夫移动模型
├── Simulator/                      # 模拟器构建
│   └── simulator_builder.py        # NS-3场景构建器
└── requirements.txt                # Python依赖
```

---

## 6. 运行指南

### 6.1 环境准备

```bash
# 1. 设置环境变量
export UAV_ROOT="/path/to/UAV"
export NS3_BIN="/path/to/ns3"
export SIMULATOR="$UAV_ROOT/simulator_builder.py"

# 2. 安装依赖
cd "$UAV_ROOT"
pip install -r requirements.txt
```

### 6.2 运行微观三臂实验

```bash
# 一键运行全部三臂实验
cd "$UAV_ROOT"
python3 experiments/run_microscopic_desync_experiment.py

# 输出位置：
# experiments/results_desync_microscopic/
#   ├── round_analysis_ack_once.json
#   ├── round_analysis_m3m4_once.json
#   ├── round_analysis_m3m4_sustained.json
#   └── figures/
#       ├── fig1_ack_sustained_n1.pdf
#       ├── fig2_m3m4_sustained_n1.pdf
#       └── fig3_m3m4_once_n1.pdf
```

### 6.3 单独运行某一臂

```bash
# 使用run_paper_experiment.py
python3 experiments/run_paper_experiment.py \
  --kind desync_boundary_micro \
  --boundary-profile ack_once \
  --protocols PMAP_ACK \
  --sizes 1

python3 experiments/run_paper_experiment.py \
  --kind desync_m3m4_sustained \
  --protocols PMAP,PMAP_ACK
```

### 6.4 仅生成图表（数据已存在）

```bash
python3 experiments/top_tier_desync/plot_top_tier_figures.py \
  --results-root experiments/results_desync_microscopic
```

---

## 7. 核心算法详解

### 7.1 PMAP_ACK自恢复机制

```python
# 关键代码: Entity/ZSP/PMAPZSP.py

# 1. 过渡窗口管理
def _stage_ack_transition(self, pid, new_pid, new_crp, ...):
    """在发送M4前记录待确认的过渡状态"""
    expires = now + self._ack_transition_grace_s()
    self._ack_pending_transition[pid] = {
        "new_pid": new_pid,
        "new_crp": new_crp,
        "expires_at": expires,
        # ... 其他会话密钥
    }

def _commit_ack_transition_if_confirmed(self, pid):
    """收到ACK后确认过渡完成"""
    if pid in self._ack_pending_transition:
        rec = self._ack_pending_transition.pop(pid)
        # 正式更新UAV数据库中的PID
        self.uav_db[rec["new_pid"]] = {...}

# 2. 攻击恢复逻辑
# 如果M4被拦截（M3/M4攻击）：
# - UAV未收到M4，仍使用旧PID
# - ZSP已有过渡记录，收到UAV的M1（旧PID）时：
#   - 检查 _ack_pending_transition
#   - 如果存在且未过期，重发M4或完成过渡
# - 双方最终状态一致
```

### 7.2 攻击检测与标记

```python
# 关键代码: experiments/top_tier_desync/round_curve_analysis.py

def analyze_log_dir_rounds(log_dir: str) -> dict:
    """分析单轮仿真日志，标记攻击轮次"""
    # 1. 从日志中检测攻击事件
    attack_times = []
    for e in events:
        if any(x in step for x in ["D2Z_ACK_SUPPRESSED", "M3_M4_INTERCEPTED"]):
            attack_times.append(e.sim_time)
    
    # 2. 将攻击时间映射到认证轮次
    attack_rounds = set()
    for at in attack_times:
        for uid, sessions in by_uav.items():
            for i, sess in enumerate(sessions):
                if sess.start_time <= at <= sess.end_time:
                    attack_rounds.add(i + 1)  # 1-based
    
    # 3. 输出带标记的轮次数据
    return {
        "rounds": [...],
        "attack_rounds": sorted(attack_rounds),
    }
```

---

## 8. 关键配置参数

### 8.1 实验预设（experiment_presets.py）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `reauth_rounds` | 120 | 单次仿真内调度的认证轮次 |
| `reauth_spacing_s` | 3.0 | 认证间隔（秒） |
| `desync_attack_min_completed_sessions` | 10 | 攻击开始轮次 |
| `desync_attack_max_completed_sessions` | 20 | 攻击结束轮次 |
| `default_seeds` | 30个 | 独立随机种子数 |
| `default_between_sleep` | 2.0 | 蜂群任务间隔（秒） |

### 8.2 攻击模型配置

```python
# Common/attack_model.py
{
    "desync_template": "boundary_m3m4_once",  # 攻击模板
    "desync_attack_first_auth_only": False,   # 是否仅攻击首次认证
    "desync_attack_min_completed_sessions": 10,
    "desync_attack_max_completed_sessions": 20,
}
```

---

## 9. 数据分析流程

### 9.1 数据流

```
NS-3仿真 → result.json → round_analysis_*.json → 图表
```

### 9.2 分析指标

| 指标 | 定义 | 用途 |
|------|------|------|
| `cumulative_successes` | 累积成功认证次数 | 叙事图Y轴 |
| `mean_success_pct` | 轮次成功率均值 | 瞬时成功率 |
| `is_attack_round` | 布尔标记 | 攻击区间标注 |
| `attack_round_span` | [min, max] | 攻击窗口范围 |

---

## 10. 扩展与维护

### 10.1 添加新协议

1. 在 `Entity/ZSP/` 创建新的ZSP类
2. 在 `Protocol/` 定义协议消息格式
3. 在 `experiment_presets.py` 添加实验配置
4. 在 `plot_top_tier_figures.py` 添加协议颜色和标记

### 10.2 添加新攻击类型

1. 在 `Common/attack_model.py` 定义攻击参数
2. 在协议代码中添加攻击检测逻辑
3. 更新 `desync_attack_template.py` 中的攻击模板

### 10.3 调试技巧

```bash
# 查看日志中的攻击标记
grep -i "attack\|intercept\|suppress" logs/*.jsonl

# 检查轮次分析是否正确标记攻击
python3 -c "
import json
d = json.load(open('experiments/results_desync_microscopic/round_analysis_ack_once.json'))
rounds = d['summary']['n1_pmap_ack']['rounds_pooled_across_seeds']
attacks = [r for r in rounds if r['is_attack_round']]
print(f'Total attack rounds: {len(attacks)}')
print(f'Attack rounds: {[r[\"round\"] for r in attacks[:10]]}...')
"
```

---

## 11. 参考文献

- 项目完整文档：`experiments/EXPERIMENTS.md`
- 实验复现指南：见本文档第6节
- 协议详细设计：`Entity/ZSP/PMAPZSP.py` 源码注释

---

**文档版本**：v1.0  
**最后更新**：2026-04-19  
**作者**：UAV-ZSP Research Team