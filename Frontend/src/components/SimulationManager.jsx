import React, { useState, useEffect, useRef } from 'react';
import './SimulationManager.css';
import ProtocolConfig from './ProtocolConfig';
import { useTasks } from '../hooks/useTasks';
import { copyToClipboard } from '../utils/helpers';
import { SCENARIOS, createMobilityStressScenario, createUplinkLossTestScenario, createDownlinkLossTestScenario } from '../utils/scenarioGenerator';
import { PROTOCOL_OPTIONS, USER_COUNT_OPTIONS, BASELINE_SCENARIO_IDS, SWARM_SIZE_OPTIONS, DENSITY_OPTIONS, GM3D_STRESS_OPTIONS, THREE_GPP_SCENARIO_OPTIONS, CARRIER_FREQUENCY_OPTIONS, LOSS_RATE_OPTIONS } from '../constants';

export const SimulationManager = () => {
  const [taskName, setTaskName] = useState('');
  const [duration, setDuration] = useState(30);
  const [selectedTask, setSelectedTask] = useState(null);
  const [copiedTaskId, setCopiedTaskId] = useState(null);
  const copyFeedbackTimerRef = useRef(null);
  const [scenarioId, setScenarioId] = useState('mobility_stress_test');
  const [protocol, setProtocol] = useState(PROTOCOL_OPTIONS[0].value);
  const [swarmSize, setSwarmSize] = useState(SWARM_SIZE_OPTIONS[0]);
  const [density, setDensity] = useState(DENSITY_OPTIONS[0].value);
  const [gm3dStress, setGm3dStress] = useState('nominal');
  const [g3ppScenario, setG3ppScenario] = useState('rma');
  const [carrierFreq, setCarrierFreq] = useState(2.4e9);
  const [lossRate, setLossRate] = useState(0.1);
  const [userCount, setUserCount] = useState(USER_COUNT_OPTIONS[0]);
  const [enableBlockchain, setEnableBlockchain] = useState(false);

  const { tasks, loading, loadTasks, createTask, runTask, getTaskDetail } = useTasks();

  const baseScenario = SCENARIOS.find((s) => s.id === scenarioId) || SCENARIOS[0];
  let activeScenario;
  
  if (baseScenario.id === 'mobility_stress_test') {
    activeScenario = createMobilityStressScenario(swarmSize, density, gm3dStress, g3ppScenario, carrierFreq);
  } else if (baseScenario.id === 'uplink_loss_test') {
    activeScenario = createUplinkLossTestScenario(swarmSize, lossRate, gm3dStress);
  } else if (baseScenario.id === 'downlink_loss_test') {
    activeScenario = createDownlinkLossTestScenario(swarmSize, lossRate, gm3dStress);
  } else {
    activeScenario = baseScenario;
  }
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

  const handleCreateTask = async (e) => {
    e.preventDefault();

    const result = await createTask({
      name: taskName || `仿真任务_${new Date().getTime()}`,
      duration,
      uavs: activeScenario.uavs,
      zsps: activeScenario.zsps,
      protocol: effectiveProtocol,
      channel: activeScenario.channel || { type: 'CSMA', datarate: '100Mbps' },
      scenario: activeScenario.id,
      scenario_profile: activeScenario.scenarioProfile || null,
      security_profile: activeScenario.security_profile || {},
      user_count: effectiveProtocol === 'RLBA_3WAY' ? userCount : 0,
      enable_blockchain: effectiveProtocol === 'RLBA_UAV' || effectiveProtocol === 'RLBA_3WAY' ? true : enableBlockchain,
    });

    if (result.success) {
      alert(`✓ 仿真任务创建成功！\n任务ID: ${result.taskId}`);
      setTaskName('');
    } else {
      alert(`✗ 创建失败: ${result.error}`);
    }
  };

  const handleRunTask = async (taskId) => {
    const result = await runTask(taskId);
    if (result.success) {
      alert(`✓ 仿真已启动！`);
    } else {
      alert(`✗ 启动失败: ${result.error}`);
    }
  };

  const handleCopyTaskId = async (taskId) => {
    const success = await copyToClipboard(taskId);
    if (success) {
      if (copyFeedbackTimerRef.current) {
        clearTimeout(copyFeedbackTimerRef.current);
      }
      setCopiedTaskId(taskId);
      copyFeedbackTimerRef.current = window.setTimeout(() => {
        setCopiedTaskId((current) => (current === taskId ? null : current));
        copyFeedbackTimerRef.current = null;
      }, 2000);
    } else {
      alert('复制失败，请检查浏览器权限或手动复制任务 ID');
    }
  };

  const handleViewTask = async (taskId) => {
    try {
      const taskDetail = await getTaskDetail(taskId);
      setSelectedTask(taskDetail);
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

          {activeScenario.supportsDensity && (
            <div className="form-group">
              <label>密度级别：</label>
              <select value={density} onChange={(e) => setDensity(parseInt(e.target.value, 10))}>
                {DENSITY_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <small>密度会影响 UAV 初始位置的间距，高密时 UAV 分布更集中。</small>
            </div>
          )}

          {activeScenario.supportsGM3DStress && (
            <div className="form-group">
              <label>GM3D 应力档位：</label>
              <select value={gm3dStress} onChange={(e) => setGm3dStress(e.target.value)}>
                {GM3D_STRESS_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <small>影响 UAV 的移动速度和稳定性，激进档位下移动更频繁。</small>
            </div>
          )}

          {activeScenario.supports3GPPScenario && (
            <div className="form-group">
              <label>3GPP 场景：</label>
              <select value={g3ppScenario} onChange={(e) => setG3ppScenario(e.target.value)}>
                {THREE_GPP_SCENARIO_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <small>选择不同的3GPP信道环境，影响路径损耗计算和通信质量。</small>
            </div>
          )}

          {activeScenario.supports3GPPScenario && (
            <div className="form-group">
              <label>载波频率：</label>
              <select value={carrierFreq} onChange={(e) => setCarrierFreq(parseFloat(e.target.value))}>
                {CARRIER_FREQUENCY_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <small>选择无线通信的载波频率，影响信号传播特性。</small>
            </div>
          )}

          {activeScenario.supportsLossRate && (
            <div className="form-group">
              <label>丢包率：</label>
              <select value={lossRate} onChange={(e) => setLossRate(parseFloat(e.target.value))}>
                {LOSS_RATE_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <small>选择丢包率，用于测试链路质量对协议的影响。</small>
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
            <label>开启区块链：</label>
            <select
              value={effectiveProtocol === "RLBA_UAV" || effectiveProtocol === "RLBA_3WAY" ? "true" : (enableBlockchain ? "true" : "false")}
              onChange={(e) => {
                if (effectiveProtocol !== "RLBA_UAV" && effectiveProtocol !== "RLBA_3WAY") {
                  setEnableBlockchain(e.target.value === "true");
                }
              }}
              disabled={effectiveProtocol === "RLBA_UAV" || effectiveProtocol === "RLBA_3WAY"}
            >
              <option value="true">True</option>
              <option value="false">False</option>
            </select>
            {effectiveProtocol === "RLBA_UAV" || effectiveProtocol === "RLBA_3WAY" ? (
              <small>RLBA协议固定开启区块链</small>
            ) : (
              <small>其他协议可选择是否开启区块链</small>
            )}
          </div>

          <div className="protocol-config-section">
            <ProtocolConfig 
              protocol={effectiveProtocol} 
              userCount={userCount} 
              setUserCount={setUserCount} 
              USER_COUNT_OPTIONS={USER_COUNT_OPTIONS} 
            />
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
        <button onClick={loadTasks} className="refresh-btn" disabled={loading}>
          {loading ? '加载中...' : '刷新列表'}
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