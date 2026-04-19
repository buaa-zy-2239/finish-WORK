import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import './SimulationManager.css';

const API_BASE = 'http://localhost:8000/api/v1';

const PROTOCOL_OPTIONS = [
  { value: 'PMAP', label: 'PMAP（经典：发完 M3/M4 即本地换 PID）' },
  { value: 'PMAP_ACK', label: 'PMAP_ACK（会话冗余：收 ZSP 的 D2Z_ACK 后才换 PID）' },
  { value: 'STATIC_BASELINE', label: 'STATIC_BASELINE（静态/预共享身份基线协议）' },
  { value: 'RLBA_UAV', label: 'RLBA_UAV（三方 AKA 的平台映射版对照协议）' },
];

const BASELINE_SCENARIO_IDS = new Set([
  'baseline_d2z',
  'pmap_ack_baseline',
  'pmap_ack_attack_drop_ack',
]);

const SWARM_SIZE_OPTIONS = [10, 30, 50, 100];

const createSwarmBurstScenario = (size, mode = 'network') => {
  const cols = 10;
  const spacingX = 22;
  const spacingY = 28;
  const triggerAt = 6;
  const uavs = Array.from({ length: size }, (_, idx) => {
    const row = Math.floor(idx / cols);
    const col = idx % cols;
    const x = -120 + col * spacingX;
    const y = -40 + row * spacingY;
    return {
      id: idx,
      mobility: {
        type: 'waypoint',
        waypoints: [
          [0, [x, y, 55]],
          [8, [x + 35, y, 55]],
          [18, [x + 80, y + 5, 55]],
        ],
      },
      auth_trigger: {
        initial_on_connect: false,
        time_offsets_s: [triggerAt],
        allow_reauth: false,
      },
      link_state: {
        comm_range_m: 320,
      },
    };
  });

  return {
    id: mode === 'compute' ? 'swarm_burst_compute' : 'swarm_burst_network',
    label: mode === 'compute' ? '阶段1.5：蜂群认证（计算敏感性）' : '阶段1.5：蜂群认证（网络拥塞）',
    description:
      mode === 'compute'
        ? '与网络拥塞场景保持相同蜂群拓扑，但在 ZSP 侧注入统一响应延迟，以模拟更重型协议计算代价。'
        : '多架 UAV 在任务启动窗口集中触发 D2Z 认证，用于观察 10/30/50/100 架规模下的并发接入压力与日志表现。',
    duration: 28,
    uavs,
    zsps: [
      {
        id: size + 1,
        position: [0, 0, 100],
        ...(mode === 'compute' ? { compute_profile: { response_delay_s: 0.12 } } : {}),
      },
    ],
    security_profile: { adversary: 'none' },
    defaultProtocol: 'PMAP_ACK',
    supportsSwarmSize: true,
    stageTag: '阶段1动态场景',
    scenarioNotes:
      mode === 'compute'
        ? ['任务启动并发触发', 'ZSP 统一响应延迟模拟重型协议', '用于主实验B子实验B：计算敏感性']
        : ['任务启动并发触发', '规模档位：10 / 30 / 50 / 100 UAV', '用于主实验B子实验A：网络拥塞'],
    triggerSummary: '任务启动时窗触发认证',
    scenarioProfile: {
      experiment_track: 'main_exp_b',
      sub_experiment: mode === 'compute' ? 'protocol_compute_sensitivity' : 'network_congestion',
      swarm_sizes: SWARM_SIZE_OPTIONS,
    },
  };
};

const SCENARIOS = [
  {
    id: 'baseline_d2z',
    label: '基线 D2Z',
    description: '双 UAV、双 ZSP，航点移动，标准 PMAP 入网认证',
    duration: 30,
    uavs: [
      { id: 0, mobility: { type: 'waypoint', waypoints: [[0, [0, 0, 50]], [10, [200, 0, 50]]] } },
      { id: 1, mobility: { type: 'waypoint', waypoints: [[0, [100, 0, 50]], [10, [300, 0, 50]]] } },
    ],
    zsps: [
      { id: 2, position: [0, 0, 100] },
      { id: 3, position: [500, 0, 100] },
    ],
    security_profile: { adversary: 'none' },
  },
  {
    id: 'single_uav_dense_zsp',
    label: '单 UAV 多 ZSP 覆盖',
    description: '一架无人机与两个地面站，便于观察切换与重复认证日志',
    duration: 45,
    uavs: [
      { id: 0, mobility: { type: 'waypoint', waypoints: [[0, [0, 0, 40]], [20, [400, 0, 40]]] } },
    ],
    zsps: [
      { id: 1, position: [0, 0, 100] },
      { id: 2, position: [200, 0, 100] },
    ],
    security_profile: { adversary: 'none' },
  },
  {
    id: 'stress_short_time',
    label: '短时压力',
    description: '较短仿真时长，用于快速回归协议与日志管道',
    duration: 15,
    uavs: [
      { id: 0, mobility: { type: 'waypoint', waypoints: [[0, [0, 0, 50]], [5, [150, 0, 50]]] } },
      { id: 1, mobility: { type: 'waypoint', waypoints: [[0, [80, 0, 50]], [5, [220, 0, 50]]] } },
    ],
    zsps: [{ id: 2, position: [0, 0, 100] }],
    security_profile: { adversary: 'none' },
  },
  {
    id: 'desync_m3m4_intercept',
    label: '去同步：ZSP 丢弃上行 M3/M4',
    description:
      'desync_template=uplink_rotation_drop：每架机仅第一次上行 M3/M4 在 ZSP 被丢弃，之后与正常信道一致，便于观察重试与恢复。PMAP_ACK 下未收 ACK 前不换 PID',
    duration: 35,
    uavs: [
      { id: 0, mobility: { type: 'waypoint', waypoints: [[0, [0, 0, 50]], [30, [120, 0, 50]]] } },
    ],
    zsps: [{ id: 2, position: [0, 0, 100] }],
    security_profile: {
      adversary: 'channel_drop',
      attack_model: {
        desync_template: 'uplink_rotation_drop',
        retry_d2z_after_intercept_s: 4,
      },
    },
  },
  {
    id: 'pmap_ack_baseline',
    label: 'PMAP_ACK 基线（无攻击）',
    description: '单 UAV 单塔，验证 D2Z_ACK 后双方再提交 PID/CRP 的正常路径',
    duration: 25,
    uavs: [
      { id: 0, mobility: { type: 'waypoint', waypoints: [[0, [0, 0, 50]], [18, [100, 0, 50]]] } },
    ],
    zsps: [{ id: 2, position: [0, 0, 100] }],
    security_profile: { adversary: 'none' },
    defaultProtocol: 'PMAP_ACK',
  },
  {
    id: 'pmap_ack_attack_drop_ack',
    label: 'PMAP_ACK：去同步（抑制 D2Z_ACK）',
    description:
      'desync_template=downlink_d2z_ack_drop：每架机仅第一次轮换在 ZSP 侧抑制 D2Z_ACK；再次 M3/M4 后正常下发 ACK 并更新库，展示超时重试后的恢复',
    duration: 30,
    uavs: [
      { id: 0, mobility: { type: 'waypoint', waypoints: [[0, [0, 0, 50]], [25, [90, 0, 50]]] } },
    ],
    zsps: [{ id: 2, position: [0, 0, 100] }],
    security_profile: {
      adversary: 'channel_drop',
      attack_model: {
        desync_template: 'downlink_d2z_ack_drop',
        d2z_ack_timeout_s: 3,
      },
    },
    defaultProtocol: 'PMAP_ACK',
  },
  {
    id: 'dynamic_edge_recovery_natural',
    label: '阶段1.5：主实验A（自然边缘恢复）',
    description:
      '单 UAV 沿固定巡检轨迹飞行，以距离 + RSSI 联合判据进入 edge 区域后触发认证，不注入恶意 ACK 抑制，用于观察 mobility-induced 恢复需求。',
    duration: 40,
    uavs: [
      {
        id: 0,
        mobility: {
          type: 'patrol',
          route: [
            [30, 0, 55],
            [180, 0, 55],
            [255, 0, 55],
            [120, 0, 55],
          ],
          dwell_s: 1.5,
          speed_mps: 14,
        },
        auth_trigger: {
          initial_on_connect: false,
          edge_rssi_threshold: -74,
          cooldown_s: 4,
          allow_reauth: false,
        },
        link_state: {
          comm_range_m: 300,
          edge_rssi_threshold: -74,
        },
      },
    ],
    zsps: [{ id: 2, position: [0, 0, 100] }],
    security_profile: { adversary: 'none' },
    defaultProtocol: 'PMAP_ACK',
    stageTag: '阶段1动态场景',
    scenarioNotes: [
      '单条巡检轨迹：30m -> 255m -> 120m',
      '联合判据：distance + RSSI + edge zone',
      '口径：mobility-induced desynchronization',
    ],
    triggerSummary: '边缘 RSSI 触发认证',
    scenarioProfile: {
      experiment_track: 'main_exp_a',
      desync_mode: 'mobility_induced',
      path_template: 'single_patrol_corridor',
      altitude_m: 55,
      speed_mps: 14,
      edge_rule: 'distance + RSSI + edge_zone',
    },
  },
  {
    id: 'dynamic_edge_recovery_attack',
    label: '阶段1.5：主实验A（攻击诱发恢复）',
    description:
      '与主实验A自然场景保持同一巡检轨迹和边缘判据，但额外在首次轮换后抑制 D2Z_ACK，用于区分 adversarial desynchronization 与 mobility-induced 场景。',
    duration: 40,
    uavs: [
      {
        id: 0,
        mobility: {
          type: 'patrol',
          route: [
            [30, 0, 55],
            [180, 0, 55],
            [255, 0, 55],
            [120, 0, 55],
          ],
          dwell_s: 1.5,
          speed_mps: 14,
        },
        auth_trigger: {
          initial_on_connect: false,
          edge_rssi_threshold: -74,
          cooldown_s: 4,
          allow_reauth: false,
        },
        link_state: {
          comm_range_m: 300,
          edge_rssi_threshold: -74,
        },
      },
    ],
    zsps: [{ id: 2, position: [0, 0, 100] }],
    security_profile: {
      adversary: 'channel_drop',
      attack_model: {
        desync_template: 'downlink_d2z_ack_drop',
        d2z_ack_timeout_s: 3,
      },
    },
    defaultProtocol: 'PMAP_ACK',
    stageTag: '阶段1动态场景',
    scenarioNotes: [
      '与自然场景共享轨迹与 edge 判据',
      '首次 ACK 抑制后恢复',
      '口径：adversarial desynchronization',
    ],
    triggerSummary: '边缘 RSSI 触发认证 + 首次 ACK 抑制',
    scenarioProfile: {
      experiment_track: 'main_exp_a',
      desync_mode: 'adversarial',
      path_template: 'single_patrol_corridor',
      altitude_m: 55,
      speed_mps: 14,
      edge_rule: 'distance + RSSI + edge_zone',
    },
  },
  {
    id: 'handover_window_reauth',
    label: '阶段1：切换窗口认证',
    description:
      '单 UAV 在两个 ZSP 覆盖区之间穿行，发生切换时在切换窗口触发认证，用于观察 handover 驱动的 D2Z 日志。',
    duration: 42,
    uavs: [
      {
        id: 0,
        mobility: {
          type: 'transit',
          start: [0, 0, 55],
          end: [420, 0, 55],
          speed_mps: 12,
        },
        auth_trigger: {
          initial_on_connect: true,
          on_handover: true,
          handover_delay_s: 0.4,
          allow_reauth: false,
        },
        link_state: {
          comm_range_m: 300,
        },
      },
    ],
    zsps: [
      { id: 2, position: [0, 0, 100] },
      { id: 3, position: [300, 0, 100] },
    ],
    security_profile: { adversary: 'none' },
    defaultProtocol: 'PMAP_ACK',
    stageTag: '阶段1动态场景',
    scenarioNotes: ['切换窗口触发认证', '双 ZSP 覆盖切换', '适合验证位置驱动 handover 触发'],
    triggerSummary: '连接建立 + 切换窗口触发认证',
  },
  {
    id: 'formation_takeoff_swarm',
    label: '阶段1：编队起飞群飞',
    description:
      '多 UAV 按编队偏移跟随统一锚点航迹，模拟编队起飞/群飞，并在任务启动窗口集中触发认证。',
    duration: 30,
    uavs: Array.from({ length: 10 }, (_, idx) => ({
      id: idx,
      mobility: {
        type: 'formation',
        anchor_waypoints: [
          [0, [0, 0, 60]],
          [8, [70, 0, 60]],
          [18, [170, 40, 60]],
        ],
        offset: [(idx % 5) * 18, Math.floor(idx / 5) * 20, 0],
      },
      auth_trigger: {
        initial_on_connect: false,
        time_offsets_s: [5],
        allow_reauth: false,
      },
      link_state: {
        comm_range_m: 330,
      },
    })),
    zsps: [{ id: 20, position: [0, 0, 100] }],
    security_profile: { adversary: 'none' },
    defaultProtocol: 'PMAP_ACK',
    stageTag: '阶段1动态场景',
    scenarioNotes: ['formation 运动模式', '群飞并发触发', '用于验证任务驱动调度器'],
    triggerSummary: '任务启动时窗触发认证',
  },
  {
    id: 'high_speed_burst_loss',
    label: '阶段1：高速转场失联恢复',
    description:
      '单 UAV 高速转场，通过预设 loss window 模拟突发失联窗口，用于观察位置相关链路波动下的认证恢复。',
    duration: 26,
    uavs: [
      {
        id: 0,
        mobility: {
          type: 'transit',
          start: [0, 0, 65],
          end: [520, 0, 65],
          speed_mps: 28,
        },
        auth_trigger: {
          initial_on_connect: false,
          time_offsets_s: [4, 10],
          allow_reauth: false,
        },
        link_state: {
          comm_range_m: 320,
          loss_windows: [
            { start_s: 4.5, end_s: 6.5, reason: 'high_speed_gap' },
          ],
        },
      },
    ],
    zsps: [{ id: 2, position: [0, 0, 100] }],
    security_profile: { adversary: 'none' },
    defaultProtocol: 'PMAP_ACK',
    stageTag: '阶段1动态场景',
    scenarioNotes: ['transit 运动模式', '预设失联窗口', '补充实验 C 的前置入口'],
    triggerSummary: '时间触发认证 + 位置关联失联窗口',
  },
  createSwarmBurstScenario(10, 'network'),
  createSwarmBurstScenario(10, 'compute'),
];

export const SimulationManager = () => {
  const [taskName, setTaskName] = useState('');
  const [duration, setDuration] = useState(30);
  const [loading, setLoading] = useState(false);
  const [tasks, setTasks] = useState([]);
  const [selectedTask, setSelectedTask] = useState(null);
  const [copiedTaskId, setCopiedTaskId] = useState(null);
  const copyFeedbackTimerRef = useRef(null);
  const [scenarioId, setScenarioId] = useState(SCENARIOS[0].id);
  const [protocol, setProtocol] = useState(PROTOCOL_OPTIONS[0].value);
  const [swarmSize, setSwarmSize] = useState(SWARM_SIZE_OPTIONS[0]);

  const baseScenario = SCENARIOS.find((s) => s.id === scenarioId) || SCENARIOS[0];
  const activeScenario =
    baseScenario.id === 'swarm_burst_network'
      ? createSwarmBurstScenario(swarmSize, 'network')
      : baseScenario.id === 'swarm_burst_compute'
        ? createSwarmBurstScenario(swarmSize, 'compute')
        : baseScenario;
  const effectiveProtocol = protocol;
  const isBaselineScenario = BASELINE_SCENARIO_IDS.has(activeScenario.id);

  useEffect(() => {
    setDuration(activeScenario.duration);
  }, [scenarioId, activeScenario.duration]);

  useEffect(() => {
    if (activeScenario.defaultProtocol) {
      setProtocol(activeScenario.defaultProtocol);
    }
  }, [scenarioId, activeScenario.defaultProtocol]);

  useEffect(() => {
    loadTasks();
  }, []);

  const handleCreateTask = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axios.post(`${API_BASE}/simulation/create`, {
        name: taskName || `仿真任务_${new Date().getTime()}`,
        duration,
        uavs: activeScenario.uavs,
        zsps: activeScenario.zsps,
        protocol: effectiveProtocol,
        channel: { type: 'CSMA', datarate: '100Mbps' },
        scenario: activeScenario.id,
        scenario_profile: activeScenario.scenarioProfile || null,
        security_profile: activeScenario.security_profile || {},
      });

      if (response.data.success) {
        alert(`✓ 仿真任务创建成功！\n任务ID: ${response.data.task_id}`);
        setTaskName('');
        loadTasks();
      }
    } catch (error) {
      alert(`✗ 创建失败: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const loadTasks = async () => {
    try {
      const response = await axios.get(`${API_BASE}/simulation/list`);
      setTasks(response.data.tasks || []);
    } catch (error) {
      console.error('Failed to load tasks:', error);
    }
  };

  const handleRunTask = async (taskId) => {
    setLoading(true);
    try {
      const response = await axios.post(`${API_BASE}/simulation/run/${taskId}`);
      if (response.data.success) {
        alert(`✓ 仿真已启动！`);
        loadTasks();
      }
    } catch (error) {
      alert(`✗ 启动失败: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleCopyTaskId = async (taskId) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(taskId);
      } else {
        const ta = document.createElement('textarea');
        ta.value = taskId;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      if (copyFeedbackTimerRef.current) {
        clearTimeout(copyFeedbackTimerRef.current);
      }
      setCopiedTaskId(taskId);
      copyFeedbackTimerRef.current = window.setTimeout(() => {
        setCopiedTaskId((current) => (current === taskId ? null : current));
        copyFeedbackTimerRef.current = null;
      }, 2000);
    } catch (err) {
      console.error(err);
      alert('复制失败，请检查浏览器权限或手动复制任务 ID');
    }
  };

  const handleViewTask = async (taskId) => {
    try {
      const configResponse = await axios.get(`${API_BASE}/simulation/config/${taskId}`);
      const statusResponse = await axios.get(`${API_BASE}/simulation/status/${taskId}`);

      setSelectedTask({
        ...statusResponse.data,
        config: configResponse.data.config,
      });
    } catch (error) {
      alert(`✗ 获取任务详情失败: ${error.message}`);
    }
  };

  return (
    <div className="simulation-manager">
      <div className="section create-section">
        <h2>创建新仿真任务</h2>
        <form onSubmit={handleCreateTask}>
          <div className="form-group">
            <label>认证场景：</label>
            <select value={scenarioId} onChange={(e) => setScenarioId(e.target.value)}>
              {SCENARIOS.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
            <p className="scenario-desc">{activeScenario.description}</p>
            <small>
              {isBaselineScenario
                ? '当前场景属于阶段0基线场景，可用于回归验证与后续实验对照起点。'
                : '当前场景属于扩展/探索场景，更适合后续动态性或规模化实验。'}
            </small>
            {activeScenario.stageTag && <small className="scenario-tag">{activeScenario.stageTag}</small>}
          </div>

          {activeScenario.supportsSwarmSize && (
            <div className="form-group">
              <label>蜂群规模：</label>
              <select value={swarmSize} onChange={(e) => setSwarmSize(parseInt(e.target.value, 10))}>
                {SWARM_SIZE_OPTIONS.map((size) => (
                  <option key={size} value={size}>
                    {size} UAV
                  </option>
                ))}
              </select>
              <small>用于阶段1的大规模并发认证实验入口，提交时将按所选规模生成 UAV 拓扑。</small>
            </div>
          )}

          <div className="form-group">
            <label>仿真协议：</label>
            <select
              value={effectiveProtocol}
              onChange={(e) => setProtocol(e.target.value)}
            >
              {PROTOCOL_OPTIONS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
            {activeScenario.defaultProtocol ? (
              <small>场景推荐协议为 {activeScenario.defaultProtocol}，但阶段2开始也可切换为其他已接入协议进行对照。</small>
            ) : (
              <small>提交任务时将使用：{effectiveProtocol}</small>
            )}
          </div>

          <div className="form-group">
            <label>任务名称（可选）：</label>
            <input
              type="text"
              value={taskName}
              onChange={(e) => setTaskName(e.target.value)}
              placeholder="自动生成 或 输入自定义名称"
            />
            <small>留空将自动生成任务名称</small>
          </div>

          <div className="form-group">
            <label>仿真时长（由场景预设，可覆盖）：</label>
            <div className="duration-input">
              <input
                type="number"
                value={duration}
                onChange={(e) => setDuration(parseInt(e.target.value, 10))}
                min="1"
                max="3600"
              />
              <span className="unit">秒</span>
            </div>
            <small>当前场景建议 {activeScenario.duration} 秒；提交时仍使用上方场景预设的时长与拓扑</small>
          </div>

          <div className="form-info">
            <p>
              <strong>当前场景拓扑：</strong> UAV {activeScenario.uavs.length} 个，ZSP {activeScenario.zsps.length}{' '}
              个；协议：<strong>{effectiveProtocol}</strong>；安全模型：
              {activeScenario.security_profile?.adversary || 'none'}
            </p>
            {activeScenario.triggerSummary && (
              <p>
                <strong>认证触发：</strong>
                {activeScenario.triggerSummary}
              </p>
            )}
            {activeScenario.scenarioProfile?.experiment_track && (
              <p>
                <strong>实验口径：</strong>
                {activeScenario.scenarioProfile.experiment_track}
                {activeScenario.scenarioProfile.sub_experiment
                  ? ` / ${activeScenario.scenarioProfile.sub_experiment}`
                  : activeScenario.scenarioProfile.desync_mode
                    ? ` / ${activeScenario.scenarioProfile.desync_mode}`
                    : ''}
              </p>
            )}
            {activeScenario.scenarioNotes?.length > 0 && (
              <ul>
                {activeScenario.scenarioNotes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            )}
          </div>

          <button type="submit" disabled={loading} className="create-btn">
            {loading ? '创建中...' : '创建任务'}
          </button>
        </form>
      </div>

      <div className="section tasks-section">
        <h2>仿真任务列表</h2>
        <button onClick={loadTasks} className="refresh-btn">
          刷新列表
        </button>

        {tasks.length === 0 ? (
          <div className="empty-state">
            <p>暂无任务</p>
            <small>创建新任务后将显示在这里</small>
          </div>
        ) : (
          <table className="tasks-table">
            <thead>
              <tr>
                <th>任务ID</th>
                <th>任务名称</th>
                <th>状态</th>
                <th>创建时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {tasks.map((task) => (
                <tr key={task.task_id}>
                  <td className="task-id-cell">
                    <span className="task-id" title={task.task_id || ''}>
                      {task.task_id && task.task_id.length > 18
                        ? `${task.task_id.slice(0, 15)}…`
                        : task.task_id || '—'}
                    </span>
                    <button
                      type="button"
                      className={`copy-task-id-btn${copiedTaskId === task.task_id ? ' copy-task-id-btn--done' : ''}`}
                      title="复制完整任务 ID（便于解析日志）"
                      aria-label="复制任务 ID"
                      disabled={!task.task_id}
                      onClick={() => handleCopyTaskId(task.task_id)}
                    >
                      {copiedTaskId === task.task_id ? '已复制' : '复制'}
                    </button>
                  </td>
                  <td>{task.name || '未命名任务'}</td>
                  <td>
                    <span className={`status-badge status-${task.status}`}>
                      {task.status === 'created' && '已创建'}
                      {task.status === 'running' && '运行中'}
                      {task.status === 'completed' && '已完成'}
                      {task.status === 'failed' && '失败'}
                    </span>
                  </td>
                  <td className="time">{new Date(task.created_at).toLocaleString('zh-CN')}</td>
                  <td className="action-buttons">
                    {task.status === 'created' && (
                      <button onClick={() => handleRunTask(task.task_id)} className="run-btn">
                        运行
                      </button>
                    )}
                    <button onClick={() => handleViewTask(task.task_id)} className="view-btn">
                      详情
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {selectedTask && (
        <div className="section task-details-section">
          <h2>任务详情</h2>
          <div className="task-details">
            <div className="detail-row">
              <span className="label">状态：</span>
              <span className={`status-badge status-${selectedTask.status}`}>
                {selectedTask.status === 'created' && '已创建'}
                {selectedTask.status === 'running' && '运行中'}
                {selectedTask.status === 'completed' && '已完成'}
                {selectedTask.status === 'failed' && '失败'}
              </span>
            </div>
            <div className="detail-row">
              <span className="label">进度：</span>
              <div className="progress-bar">
                <div className="progress-fill" style={{ width: `${selectedTask.progress || 0}%` }}>
                  {selectedTask.progress || 0}%
                </div>
              </div>
            </div>
            <div className="detail-row">
              <span className="label">创建时间：</span>
              <span>{new Date(selectedTask.created_at).toLocaleString('zh-CN')}</span>
            </div>
            {selectedTask.started_at && (
              <div className="detail-row">
                <span className="label">启动时间：</span>
                <span>{new Date(selectedTask.started_at).toLocaleString('zh-CN')}</span>
              </div>
            )}
            {selectedTask.completed_at && (
              <div className="detail-row">
                <span className="label">完成时间：</span>
                <span>{new Date(selectedTask.completed_at).toLocaleString('zh-CN')}</span>
              </div>
            )}
            <details className="config-details">
              <summary>配置详情</summary>
              <pre>{JSON.stringify(selectedTask.config, null, 2)}</pre>
            </details>
          </div>
        </div>
      )}
    </div>
  );
};

export default SimulationManager;
