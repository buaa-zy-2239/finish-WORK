import React, { useState } from 'react';
import './AnalysisDashboard.css';
import { useAnalysis } from '../hooks/useAnalysis';
import { formatNumber, formatTriggerLabel } from '../utils/helpers';

export const AnalysisDashboard = () => {
  const [taskId, setTaskId] = useState('');
  const [selectedSession, setSelectedSession] = useState(null);
  const [selectedSessionGroup, setSelectedSessionGroup] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [showTimelineModal, setShowTimelineModal] = useState(false);
  const [currentSubsessionIndex, setCurrentSubsessionIndex] = useState(0);

  const { metrics, sessions, groupedSessions, events, loading, error, loadAllData, getTimeline } = useAnalysis(taskId);

  const handleViewSessionTimeline = async (session, sessionGroup = null, subsessionIndex = 0) => {
    try {
      const sid = session.session_id || session.auth_session_id;
      const timelineData = await getTimeline(sid);
      
      setSelectedSession(session);
      setSelectedSessionGroup(sessionGroup);
      setCurrentSubsessionIndex(subsessionIndex);
      setTimeline(timelineData);
      setShowTimelineModal(true);
    } catch (err) {
      alert('加载时间线失败：' + err.message);
    }
  };

  const handleSubsessionChange = async (index) => {
    if (!selectedSessionGroup || selectedSessionGroup.sessions.length <= 1) {
      return;
    }
    const session = selectedSessionGroup.sessions[index];
    setCurrentSubsessionIndex(index);
    handleViewSessionTimeline(session, selectedSessionGroup, index);
  };

  const handleTaskIdChange = (value) => {
    if (value.includes('\n') || value.length > 100) {
      const match = value.match(/sim_\d{8}_\d{6}/);
      if (match) {
        setTaskId(match[0]);
      } else {
        setTaskId(value.split('\n')[0].slice(0, 100));
      }
    } else {
      setTaskId(value);
    }
  };

  const calculateGroupStatus = (sessions) => {
    const allSubsessionStates = {};
    let overallSuccess = false;
    let hasFailure = false;
    let hasTimeout = false;
    let pendingCount = 0;
    
    sessions.forEach(sess => {
      if (sess.subsession_states) {
        Object.entries(sess.subsession_states).forEach(([subId, state]) => {
          allSubsessionStates[subId] = state;
          if (state === 'success') overallSuccess = true;
          else if (state === 'failed') hasFailure = true;
          else if (state === 'timeout') hasTimeout = true;
        });
      }
      if (sess.session_result === 'pending' || sess.success === null) {
        pendingCount++;
      }
    });
    
    if (hasFailure) return { result: 'failed', states: allSubsessionStates };
    if (overallSuccess) return { result: 'success', states: allSubsessionStates };
    if (hasTimeout) return { result: 'timeout', states: allSubsessionStates };
    if (pendingCount > 0) return { result: 'pending', states: allSubsessionStates };
    return { result: 'pending', states: allSubsessionStates };
  };

  return (
    <div className="analysis-dashboard">
      {error && <div className="error-banner">{error}</div>}

      <div className="metrics-section task-filter">
        <h2>分析数据源</h2>
        <div className="task-id-row">
          <label htmlFor="task-id-input">任务 ID（可选，填写后读取该任务 logs 目录）：</label>
          <input
            id="task-id-input"
            type="text"
            value={taskId}
            onChange={(e) => handleTaskIdChange(e.target.value)}
            placeholder="例如 sim_20260411_173856"
          />
          <button type="button" className="refresh-btn" onClick={loadAllData} disabled={loading}>
            {loading ? '加载中...' : '应用'}
          </button>
        </div>
      </div>

      <div className="metrics-section">
        <h2>认证协议性能指标</h2>
        {metrics ? (
          <div className="metrics-grid">
            <div className="metric-card">
              <h3>认证统计</h3>
              <div className="metric-item">
                <span className="label">总会话数：</span>
                <span className="value">{metrics.authentication?.total_sessions || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">成功：</span>
                <span className="value success">{metrics.authentication?.successful || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">失败：</span>
                <span className="value error">{metrics.authentication?.failed || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">成功率：</span>
                <span className="value">{formatNumber(metrics.authentication?.success_rate_percent)}%</span>
              </div>
            </div>

            <div className="metric-card">
              <h3>消息与通信效率</h3>
              <div className="metric-item">
                <span className="label">总消息数：</span>
                <span className="value">{metrics.messaging?.total_messages || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">平均消息大小：</span>
                <span className="value">{formatNumber(metrics.messaging?.avg_size_bytes)} bytes</span>
              </div>
              <div className="metric-item">
                <span className="label">总会话字节（估算）：</span>
                <span className="value">{metrics.messaging?.total_bytes || 0} bytes</span>
              </div>
              <div className="metric-item">
                <span className="label">每成功会话平均字节：</span>
                <span className="value">
                  {formatNumber(metrics.messaging?.avg_bytes_per_successful_session)} bytes
                </span>
              </div>
              <div className="metric-item">
                <span className="label">每成功会话平均消息数：</span>
                <span className="value">
                  {formatNumber(metrics.messaging?.avg_messages_per_successful_session)}
                </span>
              </div>
            </div>

            <div className="metric-card">
              <h3>时间统计</h3>
              <div className="metric-item">
                <span className="label">平均耗时：</span>
                <span className="value">{formatNumber(metrics.timing?.avg_duration_seconds)} s</span>
              </div>
              <div className="metric-item">
                <span className="label">最小耗时：</span>
                <span className="value">{formatNumber(metrics.timing?.min_duration_seconds)} s</span>
              </div>
              <div className="metric-item">
                <span className="label">最大耗时：</span>
                <span className="value">{formatNumber(metrics.timing?.max_duration_seconds)} s</span>
              </div>
            </div>

            <div className="metric-card">
              <h3>错误统计</h3>
              <div className="metric-item">
                <span className="label">失败会话数：</span>
                <span className="value error">{metrics.errors?.total || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">M1 相关：</span>
                <span className="value">{metrics.errors?.M1_errors || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">M2 相关：</span>
                <span className="value">{metrics.errors?.M2_errors || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">M3/M4 相关：</span>
                <span className="value">{metrics.errors?.M3_M4_errors || 0}</span>
              </div>
            </div>

            <div className="metric-card">
              <h3>丢弃报文统计（未识别会话）</h3>
              <div className="metric-item">
                <span className="label">总丢弃数：</span>
                <span className="value error">{metrics.mechanism?.dropped_packets?.total || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">M1 丢弃：</span>
                <span className="value">{metrics.mechanism?.dropped_packets?.M1 || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">M2 丢弃：</span>
                <span className="value">{metrics.mechanism?.dropped_packets?.M2 || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">M3/M4 丢弃：</span>
                <span className="value">{metrics.mechanism?.dropped_packets?.M3_M4 || 0}</span>
              </div>
            </div>

            <div className="metric-card">
              <h3>触发来源</h3>
              {Object.entries(metrics.triggers?.breakdown || {}).length === 0 ? (
                <div className="metric-item">
                  <span className="label">暂无：</span>
                  <span className="value">0</span>
                </div>
              ) : (
                Object.entries(metrics.triggers?.breakdown || {}).map(([key, count]) => (
                  <div className="metric-item" key={key}>
                    <span className="label">{formatTriggerLabel(key)}：</span>
                    <span className="value">{count}</span>
                  </div>
                ))
              )}
            </div>

            <div className="metric-card">
              <h3>机制指标</h3>
              <div className="metric-item">
                <span className="label">恢复完成率：</span>
                <span className="value">
                  {formatNumber((metrics.mechanism?.recovery_completion_ratio || 0) * 100)}%
                </span>
              </div>
              <div className="metric-item">
                <span className="label">重认证额外消息：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.reauthentication_cost?.extra_messages_vs_baseline || 0)}
                </span>
              </div>
              <div className="metric-item">
                <span className="label">重认证额外字节：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.reauthentication_cost?.extra_bytes_vs_baseline || 0)}
                </span>
              </div>
              <div className="metric-item">
                <span className="label">重认证额外时延：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.reauthentication_cost?.extra_duration_vs_baseline || 0)} s
                </span>
              </div>
            </div>
          </div>
        ) : (
          <div className="loading-placeholder">{loading ? '加载中...' : '暂无数据'}</div>
        )}
      </div>

      <div className="metrics-section">
        <h2>Success vs Distance</h2>
        {metrics?.mechanism?.success_vs_distance?.length ? (
          <table className="sessions-table">
            <thead>
              <tr>
                <th>距离分桶</th>
                <th>总会话</th>
                <th>成功会话</th>
                <th>成功率</th>
              </tr>
            </thead>
            <tbody>
              {metrics.mechanism.success_vs_distance.map((item) => (
                <tr key={item.bucket}>
                  <td>{item.bucket}</td>
                  <td>{item.total_sessions}</td>
                  <td>{item.successful_sessions}</td>
                  <td>{formatNumber(item.success_rate_percent)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="loading-placeholder">暂无距离分桶数据</div>
        )}
      </div>

      <div className="sessions-section">
        <h2>认证会话列表</h2>
        <button onClick={loadAllData} className="refresh-btn" disabled={loading}>
          {loading ? '加载中...' : '刷新数据'}
        </button>

        {sessions.length === 0 ? (
          <div className="empty-state">
            <p>暂无会话数据</p>
            <small>运行仿真后填写任务 ID 或查看默认日志目录</small>
          </div>
        ) : (
          <div className="grouped-sessions">
            {Object.values(groupedSessions).map((pairGroup) => (
              <div key={pairGroup.pairKey} className="session-group">
                <h3>UAV {pairGroup.uavId} ↔ ZSP {pairGroup.zspId}</h3>
                <table className="sessions-table">
                  <thead>
                    <tr>
                      <th>会话 ID</th>
                      <th>状态</th>
                      <th>子会话状态</th>
                      <th>触发来源</th>
                      <th>耗时 (s)</th>
                      <th>消息数</th>
                      <th>字节</th>
                      <th>丢弃报文</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(pairGroup.parentSessionsArray || []).map((parentSession) => {
                      const groupStatus = calculateGroupStatus(parentSession.sessions);
                      return (
                        <tr key={parentSession.parentKey} className={groupStatus?.result === 'success' ? 'success-row' : groupStatus?.result === 'timeout' ? 'warning-row' : groupStatus?.result === 'failed' ? 'error-row' : ''}>
                          <td className="session-id-cell" title={`父会话 ${parentSession.parentKey} (${parentSession.sessions.length}个子会话)`}>
                            {parentSession.parentKey} ({parentSession.sessions.length}个子会话)
                          </td>
                          <td>
                            <span className={`status-badge ${groupStatus?.result === 'success' ? 'success' : groupStatus?.result === 'timeout' ? 'warning' : groupStatus?.result === 'failed' ? 'error' : ''}`}>
                              {groupStatus?.result === 'success' ? '成功' : groupStatus?.result === 'timeout' ? '超时' : groupStatus?.result === 'failed' ? '失败' : '待处理'}
                            </span>
                          </td>
                          <td>
                            <div className="subsession-states">
                              {Object.entries(groupStatus?.states || {}).map(([id, state]) => (
                                <span key={id} className={`subsession-badge ${state === 'success' ? 'success' : state === 'timeout' ? 'warning' : 'error'}`}>
                                  {id}: {state === 'success' ? '成功' : state === 'timeout' ? '超时' : '失败'}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td>
                            <span className="trigger-badge" title={parentSession.sessions[0]?.trigger_step || ''}>
                              {formatTriggerLabel(parentSession.sessions[0]?.trigger_reason)}
                            </span>
                          </td>
                          <td>{formatNumber(parentSession.sessions[0]?.duration_seconds)}</td>
                          <td>{parentSession.sessions.reduce((sum, s) => sum + (s.message_count || 0), 0)}</td>
                          <td>{parentSession.sessions.reduce((sum, s) => sum + (s.total_bytes || 0), 0)}</td>
                          <td>
                            {parentSession.sessions.some(s => s.dropped_packets?.total > 0) && (
                              <div className="dropped-packets-session">
                                <span className="dropped-label">
                                  丢弃: {parentSession.sessions.reduce((sum, s) => sum + (s.dropped_packets?.total || 0), 0)}
                                </span>
                              </div>
                            )}
                            {!parentSession.sessions.some(s => s.dropped_packets?.total > 0) && <span>-</span>}
                          </td>
                          <td>
                            <button onClick={() => handleViewSessionTimeline(parentSession.sessions[0], parentSession)} className="timeline-btn">
                              时间线
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                    
                    {(pairGroup.orphanSessions || []).map((session, idx) => {
                      let sessionResult = session.session_result;
                      if (!sessionResult) {
                          if (session.subsession_states) {
                              const subsessionStates = Object.values(session.subsession_states);
                              if (subsessionStates.includes('failed')) {
                                  sessionResult = 'failed';
                              } else if (subsessionStates.includes('success')) {
                                  sessionResult = 'success';
                              } else {
                                  const timeoutCount = subsessionStates.filter(state => state === 'timeout').length;
                                  sessionResult = timeoutCount >= 3 ? 'timeout' : 'timeout';
                              }
                          } else {
                              if (session.success) {
                                  sessionResult = 'success';
                              } else if (session.is_timeout || (session.phase === 'timeout') || (session.status === 'timeout')) {
                                  sessionResult = 'timeout';
                              } else if (session.error_reason) {
                                  const isFailed = session.error_reason && 
                                      (session.error_reason.includes('unknown_pid') || 
                                       session.error_reason.includes('invalid_pid') || 
                                       session.error_reason.includes('pid_mismatch') ||
                                       session.error_reason.includes('decrypt') || 
                                       session.error_reason.includes('decryption'));
                                  const isTimeout = session.error_reason && 
                                      (session.error_reason.includes('timeout') || 
                                       session.error_reason.includes('TIMEOUT') ||
                                       session.error_reason.includes('retry_budget_exhausted'));
                                  sessionResult = isFailed ? 'failed' : isTimeout ? 'timeout' : 'timeout';
                              } else {
                                  sessionResult = 'timeout';
                              }
                          }
                      }
                      return (
                        <tr key={session.session_id || idx} className={sessionResult === 'success' ? 'success-row' : sessionResult === 'timeout' ? 'warning-row' : 'error-row'}>
                          <td className="session-id-cell" title={session.session_id}>
                            {(session.session_id || '').slice(0, 12)}
                            {(session.session_id || '').length > 12 ? '…' : ''}
                          </td>
                          <td>
                            <span className={`status-badge ${sessionResult === 'success' ? 'success' : sessionResult === 'timeout' ? 'warning' : 'error'}`}>
                              {sessionResult === 'success' ? '成功' : sessionResult === 'timeout' ? '超时' : '失败'}
                            </span>
                          </td>
                          <td>
                            {session.subsession_states ? (
                              <div className="subsession-states">
                                {Object.entries(session.subsession_states).map(([id, state]) => (
                                  <span key={id} className={`subsession-badge ${state === 'success' ? 'success' : state === 'timeout' ? 'warning' : 'error'}`}>
                                    {id}: {state === 'success' ? '成功' : state === 'timeout' ? '超时' : '失败'}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span>-</span>
                            )}
                          </td>
                          <td>
                            <span className="trigger-badge" title={session.trigger_step || ''}>
                              {formatTriggerLabel(session.trigger_reason)}
                            </span>
                          </td>
                          <td>{formatNumber(session.duration_seconds)}</td>
                          <td>{session.message_count}</td>
                          <td>{session.total_bytes ?? 0}</td>
                          <td>
                            {session.dropped_packets?.total > 0 && (
                              <div className="dropped-packets-session">
                                <span className="dropped-label">丢弃: {session.dropped_packets.total}</span>
                              </div>
                            )}
                            {!session.dropped_packets?.total && <span>-</span>}
                          </td>
                          <td>
                            <button onClick={() => handleViewSessionTimeline(session, null)} className="timeline-btn">
                              时间线
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="events-section">
        <h2>最新事件</h2>
        {events.length === 0 ? (
          <div className="empty-state">
            <p>暂无事件</p>
          </div>
        ) : (
          <div className="events-list">
            {events.slice(0, 20).map((event, idx) => (
              <div key={idx} className="event-item">
                <span className="event-time">{Number(event.sim_time).toFixed(4)}s</span>
                <span className="event-type">{event.phase}</span>
                <span className="event-detail">
                  UAV{event.uav_id} → ZSP{event.zsp_id}
                  {event.protocol_step ? ` · ${event.protocol_step}` : ''}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="metrics-section">
        <h2>机动应力分析</h2>
        {metrics?.mechanism?.recovery_completion_ratio !== undefined && (
          <div className="metrics-grid">
            <div className="metric-card">
              <h3>恢复性能</h3>
              <div className="metric-item">
                <span className="label">恢复完成率：</span>
                <span className="value">
                  {formatNumber((metrics.mechanism.recovery_completion_ratio || 0) * 100)}%
                </span>
              </div>
              <div className="metric-item">
                <span className="label">重试成功率：</span>
                <span className="value">
                  {formatNumber((metrics.mechanism.reauthentication_cost?.retry_successes || 0))}
                </span>
              </div>
              <div className="metric-item">
                <span className="label">重认证额外消息：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.reauthentication_cost?.extra_messages_vs_baseline || 0)}
                </span>
              </div>
              <div className="metric-item">
                <span className="label">重认证额外字节：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.reauthentication_cost?.extra_bytes_vs_baseline || 0)}
                </span>
              </div>
              <div className="metric-item">
                <span className="label">重认证额外时延：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.reauthentication_cost?.extra_duration_vs_baseline || 0)} s
                </span>
              </div>
            </div>

            <div className="metric-card">
              <h3>移动性影响</h3>
              <div className="metric-item">
                <span className="label">平均速度：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.mobility_metrics?.avg_speed_mps || 0)} m/s
                </span>
              </div>
              <div className="metric-item">
                <span className="label">最大速度：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.mobility_metrics?.max_speed_mps || 0)} m/s
                </span>
              </div>
              <div className="metric-item">
                <span className="label">平均加速度：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.mobility_metrics?.avg_acceleration_mps2 || 0)} m/s²
                </span>
              </div>
              <div className="metric-item">
                <span className="label">拓扑动态性：</span>
                <span className="value">
                  {metrics.mechanism?.mobility_metrics?.topology_dynamicity || '未知'}
                </span>
              </div>
              <div className="metric-item">
                <span className="label">预期链路寿命：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.mobility_metrics?.expected_link_lifetime_s || 0)} s
                </span>
              </div>
            </div>

            <div className="metric-card">
              <h3>子会话分析</h3>
              <div className="metric-item">
                <span className="label">平均子会话数：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.subsession_metrics?.avg_subsessions_per_session || 0)}
                </span>
              </div>
              <div className="metric-item">
                <span className="label">子会话成功率：</span>
                <span className="value">
                  {formatNumber((metrics.mechanism?.subsession_metrics?.subsession_success_rate || 0) * 100)}%
                </span>
              </div>
              <div className="metric-item">
                <span className="label">子会话平均时长：</span>
                <span className="value">
                  {formatNumber(metrics.mechanism?.subsession_metrics?.avg_subsession_duration_s || 0)} s
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {showTimelineModal && selectedSession && (
        <div className="timeline-modal-overlay">
          <div className="timeline-modal">
            <div className="timeline-modal-header">
              <h2>
                {selectedSessionGroup ? (
                  <>父会话时间线 — UAV {selectedSession.uav_id} → ZSP {selectedSession.zsp_id} ({selectedSessionGroup.parentKey})</>
                ) : (
                  <>会话时间线 — UAV {selectedSession.uav_id} → ZSP {selectedSession.zsp_id}</>
                )}
                {selectedSession.session_id && !selectedSessionGroup ? ` (${selectedSession.session_id.slice(0, 8)}…)` : ''}
                {selectedSessionGroup && selectedSessionGroup.sessions.length > 1 && (
                  <span className="subsession-count"> ({selectedSessionGroup.sessions.length}个子会话)</span>
                )}
              </h2>
              <button className="close-btn" onClick={() => setShowTimelineModal(false)}>
                ×
              </button>
            </div>
            {selectedSessionGroup && selectedSessionGroup.sessions.length > 1 && (
              <div className="subsession-tabs">
                <button
                  className="nav-btn"
                  onClick={() => handleSubsessionChange(Math.max(0, currentSubsessionIndex - 1))}
                  disabled={currentSubsessionIndex === 0}
                >
                  ←
                </button>
                <div className="subsession-dots">
                  {selectedSessionGroup.sessions.map((sess, idx) => (
                    <button
                      key={idx}
                      className={`subsession-dot ${idx === currentSubsessionIndex ? 'active' : ''}`}
                      onClick={() => handleSubsessionChange(idx)}
                      title={`子会话 ${idx} (${sess.session_result || '未知'})`}
                    >
                      {idx + 1}
                    </button>
                  ))}
                </div>
                <button
                  className="nav-btn"
                  onClick={() => handleSubsessionChange(Math.min(selectedSessionGroup.sessions.length - 1, currentSubsessionIndex + 1))}
                  disabled={currentSubsessionIndex === selectedSessionGroup.sessions.length - 1}
                >
                  →
                </button>
              </div>
            )}
            <div className="timeline-modal-body">
              {timeline && timeline.steps && timeline.steps.length > 0 ? (
                <div className="sequence-diagram">
                  <div className="sequence-diagram-header">
                    <div className="participant uav">UAV {timeline.uav_id || selectedSession.uav_id}</div>
                    <div className="participant zsp">ZSP {timeline.zsp_id || selectedSession.zsp_id}</div>
                  </div>
                  <div className="sequence-diagram-content">
                    {timeline.steps.map((step, idx) => {
                      let direction = 'uav-to-zsp';
                      let isPacketDrop = false;
                      let isError = false;
                      let messageType = 'Unknown';
                      let errorReason = null;
                      
                      const nextStep = timeline.steps[idx + 1];
                      const isFollowedByTimeout = nextStep && nextStep.diagram && nextStep.diagram.includes('-X');
                      
                      if (step.diagram) {
                        if (step.diagram.includes('UAV -> ZSP')) {
                          const currentMsg = step.diagram.replace('UAV -> ZSP: ', '');
                          if (isFollowedByTimeout && nextStep.diagram.startsWith(currentMsg + ' -')) {
                            return null;
                          }
                          direction = 'uav-to-zsp';
                          messageType = currentMsg;
                        } else if (step.diagram.includes('ZSP received')) {
                          direction = 'zsp-to-uav';
                          messageType = step.diagram.replace('ZSP received ', 'received ');
                        } else if (step.diagram.includes('ZSP -> UAV')) {
                          const currentMsg = step.diagram.replace('ZSP -> UAV: ', '');
                          if (isFollowedByTimeout && nextStep.diagram.startsWith(currentMsg + ' -')) {
                            return null;
                          }
                          direction = 'zsp-to-uav';
                          messageType = currentMsg;
                        } else if (step.diagram.includes('UAV received')) {
                          direction = 'uav-to-zsp';
                          messageType = step.diagram.replace('UAV received ', 'received ');
                        } else if (step.diagram.includes('Success')) {
                          direction = 'uav-to-zsp';
                          messageType = '认证成功';
                        } else if (step.diagram.includes('-X')) {
                          isError = true;
                          const beforeDash = step.diagram.split(' -')[0].trim();
                          if (beforeDash === 'M1/M2') {
                            direction = 'uav-to-zsp';
                            messageType = 'M1/M2';
                          } else if (beforeDash === 'M3/M4') {
                            direction = 'uav-to-zsp';
                            messageType = 'M3/M4';
                          } else if (beforeDash === 'M2') {
                            direction = 'zsp-to-uav';
                            messageType = 'M2';
                          } else if (beforeDash === 'ACK') {
                            direction = 'zsp-to-uav';
                            messageType = 'ACK';
                          } else if (beforeDash === 'M1') {
                            direction = 'uav-to-zsp';
                            messageType = 'M1';
                          }
                          const match = step.diagram.match(/\((.*?)\)/);
                          if (match) {
                            errorReason = match[1];
                          }
                        } else {
                          messageType = step.diagram;
                        }
                      }
                      
                      if (step.to?.startsWith('FAILED_')) {
                        isError = true;
                        if (!errorReason) {
                          errorReason = step.error_reason || step.to.replace('FAILED_', '').replace('_', ' ').toLowerCase();
                        }
                      }
                      
                      if (step.error_reason?.includes('dropped') || step.message_type?.includes('DROPPED')) {
                        isPacketDrop = true;
                        isError = true;
                        errorReason = errorReason || '丢包';
                      }
                      
                      return (
                        <div key={idx} className="sequence-item">
                          <div className="sequence-time">{step.sim_time?.toFixed(4) || idx}s</div>
                          <div className="sequence-message-container">
                            {direction === 'uav-to-zsp' ? (
                              <div className="message-sender uav-side">
                                <div className={`message-bubble ${isError ? 'error' : ''} ${isPacketDrop ? 'packet-drop' : ''}`}>
                                  <div className="message-type">{messageType}</div>
                                  {errorReason && (
                                    <div className="message-note">{errorReason}</div>
                                  )}
                                </div>
                                <div className={`message-arrow uav-to-zsp ${isError ? 'error' : ''} ${isPacketDrop ? 'packet-drop' : ''}`}>
                                  {isError && (
                                    <div className="error-mark">×</div>
                                  )}
                                </div>
                              </div>
                            ) : (
                              <div className="message-sender zsp-side">
                                <div className={`message-arrow zsp-to-uav ${isError ? 'error' : ''} ${isPacketDrop ? 'packet-drop' : ''}`}>
                                  {isError && (
                                    <div className="error-mark">×</div>
                                  )}
                                </div>
                                <div className={`message-bubble ${isError ? 'error' : ''} ${isPacketDrop ? 'packet-drop' : ''}`}>
                                  <div className="message-type">{messageType}</div>
                                  {errorReason && (
                                    <div className="message-note">{errorReason}</div>
                                  )}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  {timeline.result && (
                    <div className="sequence-diagram-footer">
                      <span className={`result-badge ${timeline.result === 'success' ? 'success' : timeline.result === 'timeout' ? 'warning' : 'failed'}`}>
                        {timeline.result === 'success' ? '✓ 认证成功' : timeline.result === 'timeout' ? '⏱️ 超时' : '✗ 认证失败'}
                      </span>
                      {timeline.error_reason && (
                        <span className="error-reason">{timeline.error_reason}</span>
                      )}
                    </div>
                  )}
                </div>
              ) : (
                <div className="loading-placeholder">暂无时间线数据</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AnalysisDashboard;