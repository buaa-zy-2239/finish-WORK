# UAV网络安全认证协议实验设计与前端展示方案

## 一、当前实验设计分析

### 1.1 当前UAV数量设置
| 实验类型 | UAV数量 | 说明 |
|---------|--------|------|
| baseline | 10,30 | 默认基础实验 |
| scalability | 10,30,50 | 规模可扩展性测试 |
| S02 (机动应力) | 10,30 | 当前使用的数量 |

### 1.2 实验设计充分性问题

**问题1：UAV数量覆盖不足**
- 当前机动应力实验仅使用 N=10,30 两个数量级别
- 建议补充 N=50,100 以形成完整的规模梯度
- 统计显著性：每个数量级别至少30个独立种子

**问题2：密度档位单一**
- 当前 S02 实验仅使用 ρ=1 (low)
- 建议增加 ρ=10 (medium), ρ=50 (high) 形成密度对比

---

## 二、实验设计改进建议

### 2.1 机动应力实验规模扩展

**推荐矩阵设计：**

| 网络规模(N) | 密度(ρ) | GM3D应力档位 | 种子数 |
|------------|---------|--------------|--------|
| 10, 30, 50, 100 | 1, 10, 50 | conservative, nominal, aggressive | 30 |

**关键参数说明：**
- **网络规模 N**：10（小型蜂群）、30（中型蜂群）、50（大型蜂群）、100（超大规模）
- **密度 ρ**：1 UAV/km²（稀疏）、10 UAV/km²（中等）、50 UAV/km²（密集）
- **GM3D应力档位**：
  - conservative: 3±2 m/s（低速稳定）
  - nominal: 5±5 m/s（中等动态）
  - aggressive: 12±7 m/s（高机动性）

### 2.2 统计显著性要求

```python
# experiment_presets.py 中的推荐配置
@dataclass
class SwarmMatrix:
    # 每个实验配置至少30个独立种子
    default_seeds: str = "20260417,...,20260516"  # 30个种子

    # 统计最小样本量
    min_runs_for_statistical_analysis: int = 30

    # 置信度要求
    confidence_level: float = 0.95  # 95%置信区间
```

---

## 三、前端展示场景设计方案

### 3.1 设计目标

为前端可视化设计一个**实时交互式无人机网络安全认证演示系统**，让用户能够：
1. 直观理解无人机网络认证协议的工作原理
2. 观察不同场景下协议的性能表现
3. 交互式调整参数并实时观察结果

### 3.2 推荐展示场景类型

#### 场景1：基础认证流程可视化
**描述**：展示单个无人机与ZSP之间的完整D2Z认证握手过程

**可交互参数**：
- 协议类型：PMAP / PMAP_ACK
- 信道质量：优/中/差
- 是否启用重传

**展示内容**：
- 消息序列图（M1→M2→M3/M4→ACK）
- 实时状态转换：INITIATED → CHALLENGING → ACCEPTED/FAILED
- 计时器可视化

#### 场景2：多无人机蜂群认证
**描述**：展示多个无人机同时与ZSP进行认证的场景

**可交互参数**：
- UAV数量：1-20（前端演示用）
- 认证协议：PMAP / PMAP_ACK
- 攻击模式：无攻击 / 去同步攻击

**展示内容**：
- 2D拓扑图：无人机位置、移动轨迹
- 认证状态热力图
- 成功/失败实时计数器

#### 场景3：机动性压力测试
**描述**：展示不同机动性档位下的协议性能对比

**可交互参数**：
- 运动模型：Gauss-Markov 3D
- 机动档位：conservative / nominal / aggressive
- 仿真时长：30s / 60s / 120s

**展示内容**：
- 3D轨迹可视化（X-Y-Z 位置随时间变化）
- 认证成功率实时曲线
- 平均认证延迟对比

#### 场景4：去同步攻击演示
**描述**：展示中间人攻击下的协议恢复能力

**可交互参数**：
- 攻击类型：无攻击 / M3/M4丢弃 / ACK抑制
- 攻击时机：首轮 / 中途（第N轮）
- 协议类型：PMAP / PMAP_ACK

**展示内容**：
- 攻击时间线标注
- 会话状态机可视化
- 恢复机制展示

---

## 四、前端交互设计规格

### 4.1 控制面板规格

```yaml
控制面板:
  - 网络规模滑块: 1-100 UAVs
  - 密度选择器: low(1) / medium(10) / high(50) UAV/km²
  - 协议单选: PMAP / PMAP_ACK
  - 运动模型选择: gauss_markov_3d
  - GM3D档位: conservative / nominal / aggressive
  - 攻击开关: 启用/禁用
  - 攻击类型: M3M4拦截 / ACK抑制
  - 仿真时长: 30s / 60s / 120s
  - 种子选择: 单种子 / 多种子平均
```

### 4.2 可视化面板规格

```yaml
主可视化区:
  - 2D拓扑图: 无人机位置、ZSP位置、连接线
  - 3D轨迹视图: 完整三维轨迹动画
  - 消息序列图: 协议握手时序
  - 实时数据面板:
    - 成功率 (%)
    - 平均延迟 (ms)
    - 超时次数
    - 密钥不匹配次数
```

### 4.3 性能指标展示

| 指标 | 说明 | 可视化形式 |
|------|------|-----------|
| Session Completion Rate | 成功完成率 | 百分比 + 趋势线 |
| Avg Duration | 平均认证时长 | 柱状图对比 |
| Timeout Rate | 超时率 | 饼图 |
| Key Mismatch Rate | 密钥不匹配率 | 折线图 |
| Handover Rate | 切换率 | 热力图 |

---

## 五、技术实现建议

### 5.1 前端技术栈

- **框架**：React + TypeScript
- **3D可视化**：Three.js / React-Three-Fiber
- **2D拓扑**：D3.js / Cytoscape.js
- **实时数据**：WebSocket / Socket.IO
- **UI组件**：Ant Design / Material-UI

### 5.2 数据交互接口

```typescript
// 推荐的前端-后端接口设计
interface ExperimentConfig {
  n_uavs: number;           // 1-100
  density: number;          // 1, 10, 50
  protocol: 'PMAP' | 'PMAP_ACK';
  motion_mode: 'gauss_markov_3d';
  gm_stress: 'conservative' | 'nominal' | 'aggressive';
  attack_enabled: boolean;
  attack_type: 'none' | 'm3m4_drop' | 'ack_suppress';
  duration_seconds: number;
  seed: number;
}

interface ExperimentResult {
  success_rate: number;
  avg_duration_ms: number;
  timeout_count: number;
  key_mismatch_count: number;
  trajectory_data: TrajectoryPoint[];
  event_log: AuthEvent[];
}
```

### 5.3 推荐预计算场景

为前端演示，建议预计算以下场景的实验数据：

1. **基础性能基线**：N=10/30/50，ρ=1，无攻击
2. **机动性对比**：N=30，ρ=1，三档GM应力对比
3. **密度影响**：N=30，ρ=1/10/50，nominal GM
4. **攻击恢复演示**：N=10，ρ=1，PMAP_ACK + ACK抑制攻击

---

## 六、结论

1. **实验设计改进**：建议将机动应力实验的UAV数量扩展到10/30/50/100，并增加密度档位对比，以支撑更充分的实验结论

2. **前端展示设计**：推荐设计4个核心交互场景，分别展示基础认证流程、多无人机蜂群认证、机动性压力测试、去同步攻击演示

3. **技术实现路径**：建议采用预计算+实时查询混合模式，确保前端演示的流畅性和交互性