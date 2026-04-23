import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import './AnalysisDashboard.css';

const API_BASE = 'http://localhost:8000/api/v1';

export const AnalysisDashboard = () => {
  const [metrics, setMetrics] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [groupedSessions, setGroupedSessions] = useState({});
  const [events, setEvents] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [showTimelineModal, setShowTimelineModal] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [taskId, setTaskId] = useState('');
  const [currentSubsessionIndex, setCurrentSubsessionIndex] = useState(0);

  const loadAllData = useCallback(async () => {
    setLoading(true);
    setError(null);
    const t = taskId.trim();
    const qp = t ? { task_id: t } : {};
    try {
      const results = await Promise.allSettled([
        axios.get(`${API_BASE}/metrics/summary`, { params: qp }),
        axios.get(`${API_BASE}/analysis/sessions`, { params: qp }),
        axios.get(`${API_BASE}/analysis/events`, { params: { limit: 80, ...qp } }),
      ]);

      if (results[0].status === 'fulfilled') {
        setMetrics(results[0].value.data.metrics);
      } else {
        console.error('Failed to load metrics:', results[0].reason);
      }

      if (results[1].status === 'fulfilled') {
        const sessionData = results[1].value.data.sessions || [];
        setSessions(sessionData);
        
        // 按UAV-ZSP对分组，并按时间顺序排序
        const grouped = sessionData.reduce((acc, session) => {
          const key = `${session.uav_id}-${session.zsp_id}`;
          if (!acc[key]) {
            acc[key] = {
              uavId: session.uav_id,
              zspId: session.zsp_id,
              sessions: []
            };
          }
          acc[key].sessions.push(session);
          return acc;
        }, {});
        
        // 对每个分组内的会话按时间顺序排序
        Object.values(grouped).forEach(group => {
          group.sessions.sort((a, b) => {
            // 尝试使用不同的时间字段进行排序
            const timeA = a.start_time || a.sim_time || 0;
            const timeB = b.start_time || b.sim_time || 0;
            return timeA - timeB;
          });
        });
        
        setGroupedSessions(grouped);
      } else {
        console.error('Failed to load sessions:', results[1].reason);
        setSessions([]);
        setGroupedSessions({});
      }

      if (results[2].status === 'fulfilled') {
        setEvents(results[2].value.data.events || []);
      } else {
        console.error('Failed to load events:', results[2].reason);
        setEvents([]);
      }
    } catch (err) {
      console.error('Failed to load data:', err);
      setError('加载数据失败，请稍后重试');
    } finally {
      setLoading(false);
    }
  }, [taskId]);

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 5000);
    return () => clearInterval(interval);
  }, [loadAllData]);

  const handleViewSessionTimeline = async (session) => {
    try {
      const sid = session.session_id || session.auth_session_id;
      const tid = taskId.trim();
      const qp = tid ? { task_id: tid } : {};
      const response = await axios.get(
        `${API_BASE}/analysis/sessions/${session.uav_id}/${session.zsp_id}/timeline`,
        { params: { ...qp, ...(sid ? { session_id: sid } : {}) } }
      );
      setSelectedSession(session);
      setCurrentSubsessionIndex(0); // 重置子会话索引为0
      setTimeline(response.data.timeline || []);
      setShowTimelineModal(true);
    } catch (err) {
      console.error('Failed to load timeline:', err);
      alert('加载时间线失败：' + (err.response?.data?.detail || err.message));
    }
  };

  const formatNumber = (num) => {
    if (typeof num !== 'number' || Number.isNaN(num)) return num;
    return num.toFixed(2);
  };

  const formatTriggerLabel = (trigger) => {
    switch (trigger) {
      case 'edge_rssi':
        return '边缘 RSSI';
      case 'time_window':
        return '任务时间窗';
      case 'connect':
        return '连接建立';
      case 'retry':
        return '重试恢复';
      case 'handover_window':
        return '切换窗口';
      default:
        return trigger || '未知';
    }
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
            onChange={(e) => setTaskId(e.target.value)}
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
            {Object.values(groupedSessions).map((group) => {
              const pairKey = `${group.uavId}-${group.zspId}`;
              const droppedPackets = metrics?.mechanism?.dropped_packets_by_pair?.[pairKey] || { M1: 0, M2: 0, M3_M4: 0, total: 0 };
              
              return (
                <div key={pairKey} className="session-group">
                  <h3>UAV {group.uavId} ↔ ZSP {group.zspId}</h3>
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
                      {group.sessions.map((session, idx) => {
                        // 确定认证会话的结果
                        // 认证会话的结果基于所有子会话的结果
                        let sessionResult = session.session_result;
                        if (!sessionResult) {
                            // 检查子会话状态
                            if (session.subsession_states) {
                                const subsessionStates = Object.values(session.subsession_states);
                                // 若子会话中状态字段为失败，则会话状态为失败
                                if (subsessionStates.includes('failed')) {
                                    sessionResult = 'failed';
                                } 
                                // 若子会话状态为成功，则会话状态为成功
                                else if (subsessionStates.includes('success')) {
                                    sessionResult = 'success';
                                } 
                                // 若子会话状态多次为超时，且超时重试超过阈值，有日志体现，则会话状态为超时
                                else {
                                    const timeoutCount = subsessionStates.filter(state => state === 'timeout').length;
                                    if (timeoutCount >= 3) { // 假设重试阈值为3
                                        sessionResult = 'timeout';
                                    } else {
                                        // 其他情况默认为超时
                                        sessionResult = 'timeout';
                                    }
                                }
                            } else {
                                // 没有子会话状态信息时的默认判断
                                if (session.success) {
                                    sessionResult = 'success';
                                } else if (session.is_timeout || (session.phase === 'timeout') || (session.status === 'timeout')) {
                                    sessionResult = 'timeout';
                                } else if (session.error_reason) {
                                    // 检查错误原因是否包含失败相关信息
                                    const isFailed = session.error_reason && 
                                        (session.error_reason.includes('unknown_pid') || 
                                         session.error_reason.includes('invalid_pid') || 
                                         session.error_reason.includes('pid_mismatch') ||
                                         session.error_reason.includes('decrypt') || 
                                         session.error_reason.includes('decryption'));
                                    // 检查错误原因是否包含超时相关信息
                                    const isTimeout = session.error_reason && 
                                        (session.error_reason.includes('timeout') || 
                                         session.error_reason.includes('TIMEOUT') ||
                                         session.error_reason.includes('retry_budget_exhausted'));
                                    if (isFailed) {
                                        sessionResult = 'failed';
                                    } else if (isTimeout) {
                                        sessionResult = 'timeout';
                                    } else {
                                        sessionResult = 'timeout';
                                    }
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
                              <button onClick={() => handleViewSessionTimeline(session)} className="timeline-btn">
                                时间线
                              </button>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              );
            })}
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
            </div>
          </div>
        )}
      </div>

      {/* 时间线模态框 */}
      {showTimelineModal && selectedSession && (
        <div className="timeline-modal-overlay">
          <div className="timeline-modal">
            <div className="timeline-modal-header">
              <h2>
                会话时间线 — UAV {selectedSession.uav_id} → ZSP {selectedSession.zsp_id}
                {selectedSession.session_id ? ` (${selectedSession.session_id.slice(0, 8)}…)` : ' (未识别会话)'}
              </h2>
              <button className="close-btn" onClick={() => setShowTimelineModal(false)}>
                ×
              </button>
            </div>
            <div className="timeline-modal-body">
              {timeline.length > 0 ? (
                <div className="sequence-diagram">
                  <div className="sequence-diagram-header">
                    <div className="participant uav">UAV {selectedSession.uav_id}</div>
                    <div className="participant zsp">ZSP {selectedSession.zsp_id}</div>
                  </div>
                  <div className="sequence-diagram-content">
                    {(() => {
                      // 处理事件：过滤重复事件，确保正确的时序关系
                      
                      // 首先按时间排序（确保时序正确），对于相同时间的事件，按逻辑顺序排序
                      const sortedEvents = [...timeline].sort((a, b) => {
                        // 首先按subSessionId排序（null或0的排在前面）
                        const subA = a.subsession_id ?? 0;
                        const subB = b.subsession_id ?? 0;
                        if (subA !== subB) {
                          return subA - subB;
                        }
                        // 然后按sim_time排序
                        const timeDiff = (a.sim_time || 0) - (b.sim_time || 0);
                        if (timeDiff !== 0) {
                          return timeDiff;
                        }
                        
                        // 对于相同时间的事件，按逻辑顺序排序
                        const eventPriority = (event) => {
                          // 事件优先级：会话建立 < 消息发送 < 丢包 < 重试 < 消息接收 < ACK < 会话密钥建立 < 成功 < 超时
                          if (event.phase === 'initiated' && !event.protocol_step?.includes('RETRY')) return 1;
                          if (event.phase === 'M1_sent' && event.success === true) return 2;
                          if (event.success === false && (event.error_reason?.includes('dropped') || event.protocol_step?.includes('DROPPED'))) return 3;
                          if (event.event_type?.includes('RETRY') || event.protocol_step?.includes('RETRY_AFTER')) return 4;
                          if (event.phase === 'M2_sent' || event.phase === 'M3_M4_sent') return 5;
                          if (event.phase === 'M2_received') return 6;
                          if (event.phase === 'ack_received') return 6.5;
                          if (event.phase === 'session_key_established') return 7;
                          if (event.phase === 'success') return 8;
                          if (event.phase === 'timeout' || event.protocol_step?.includes('RETRY_BUDGET_EXHAUSTED')) return 9;
                          return 10; // 其他事件
                        };
                        
                        return eventPriority(a) - eventPriority(b);
                      });
                      
                      // 按子会话ID分组
                      const subsessionGroups = {};
                      
                      // 遍历事件，按子会话ID分组
                      for (const item of sortedEvents) {
                        // 过滤掉M1_received事件
                        if (item.phase === 'M1_received') continue;
                        // 过滤掉M3_M4_sent事件，但保留M3/M4_RECV和DROPPED事件
                        if (item.phase === 'M3_M4_sent' && !item.protocol_step?.includes('DROPPED') && !item.protocol_step?.includes('M3_M4_RECV')) continue;
                        // 过滤掉M1重试事件
                        if (item.event_type?.includes('RETRY') || item.protocol_step?.includes('RETRY_AFTER') || item.protocol_step?.includes('ATTACK_RETRY') || item.message_type === 'RETRY') continue;
                        // 过滤掉UAV侧的会话密钥建立和认证成功事件
                        if (item.entity_type === 'UAV' && (item.phase === 'session_key_established' || item.phase === 'success')) continue;
                        
                        // 确定子会话ID
                        let subsessionKey = item.subsession_id !== null && item.subsession_id !== undefined ? item.subsession_id : 0;
                        
                        // 为每个子会话分组添加事件
                        if (!subsessionGroups[subsessionKey]) {
                          subsessionGroups[subsessionKey] = [];
                        }
                        subsessionGroups[subsessionKey].push(item);
                      }
                      
                      // 渲染分组
                      const renderSubsessionGroup = (events, subsessionKey) => {
                        const groupFilteredEvents = [];
                        const groupTimeoutSeen = new Set();
                        const groupM1SentSeen = new Set();
                        const groupM3m4SentSeen = new Set();
                        
                        for (const item of events) {
                          // 4. 每个子会话只保留一个超时事件
                          if (item.phase === 'timeout' || item.protocol_step?.includes('RETRY_BUDGET_EXHAUSTED')) {
                            const sessionKey = `${item.uav_id}-${item.zsp_id}-${item.auth_session_id}-${subsessionKey}`;
                            if (groupTimeoutSeen.has(sessionKey)) {
                              continue;
                            }
                            groupTimeoutSeen.add(sessionKey);
                          }
                          
                          // 5. 每个子会话过滤掉重复的M1发送事件
                          if (item.phase === 'M1_sent' && item.success === true) {
                            const m1Key = `${item.uav_id}-${item.zsp_id}-${item.auth_session_id}-${subsessionKey}`;
                            if (groupM1SentSeen.has(m1Key)) {
                              continue;
                            }
                            groupM1SentSeen.add(m1Key);
                          }
                          
                          // 6. 每个子会话过滤掉重复的M3_M4发送事件
                          if (item.phase === 'M3_M4_sent' && item.success === true) {
                            const m3m4Key = `${item.uav_id}-${item.zsp_id}-${item.auth_session_id}-${subsessionKey}`;
                            if (groupM3m4SentSeen.has(m3m4Key)) {
                              continue;
                            }
                            groupM3m4SentSeen.add(m3m4Key);
                          }
                          
                          // 7. 确保会话结果的唯一性：如果子会话有成功事件，过滤掉所有超时事件
                          if (item.phase === 'timeout' || item.protocol_step?.includes('RETRY_BUDGET_EXHAUSTED')) {
                            // 只检查当前子会话的事件
                            const hasSuccessEvent = events.some(e => 
                              e.uav_id === item.uav_id && 
                              e.zsp_id === item.zsp_id && 
                              e.auth_session_id === item.auth_session_id && 
                              e.phase === 'success' &&
                              (e.subsession_id === subsessionKey || (e.subsession_id === null || e.subsession_id === undefined))
                            );
                            if (hasSuccessEvent) {
                              continue;
                            }
                          }
                          
                          // 8. 确保会话结果的唯一性：如果子会话有超时事件，过滤掉成功事件（如果超时事件在成功事件之后）
                          if (item.phase === 'success') {
                            // 只检查当前子会话的事件
                            const hasLaterTimeoutEvent = events.some(e => 
                              e.uav_id === item.uav_id && 
                              e.zsp_id === item.zsp_id && 
                              e.auth_session_id === item.auth_session_id && 
                              (e.phase === 'timeout' || e.protocol_step?.includes('RETRY_BUDGET_EXHAUSTED')) && 
                              e.sim_time > item.sim_time &&
                              (e.subsession_id === subsessionKey || (e.subsession_id === null || e.subsession_id === undefined))
                            );
                            if (hasLaterTimeoutEvent) {
                              continue;
                            }
                          }
                          
                          groupFilteredEvents.push(item);
                        }
                        
                        // 渲染子会话分组
                        return groupFilteredEvents.map((item, idx) => {
                          let direction = 'uav-to-zsp';
                          let isPacketDrop = false;
                          let isRetry = false;
                          let isTimeout = false;
                          let messageType = 'Unknown';
                          
                          // 确定消息方向和类型
                          if (item.event_type?.includes('RETRY') || item.protocol_step?.includes('RETRY_AFTER') ||
                              item.protocol_step?.includes('ATTACK_RETRY') || item.message_type === 'RETRY') {
                            direction = 'uav-to-zsp';
                            messageType = 'M1';
                            isRetry = true;
                          } else if (item.phase === 'M1_sent' || item.message_type === 'M1') {
                            direction = 'uav-to-zsp';
                            messageType = 'M1';
                          } else if (item.phase === 'M2_sent' || item.phase === 'M2_received' || item.message_type === 'M2') {
                            direction = 'zsp-to-uav';
                            messageType = 'M2';
                          } else if (item.phase === 'ack_received' || item.message_type === 'D2Z_ACK') {
                            direction = 'zsp-to-uav';
                            messageType = 'ACK';
                          } else if (item.phase === 'M3_M4_received' || item.message_type === 'M3/M4' || item.protocol_step?.includes('M3_M4_RECV') || (item.phase === 'M3_M4_sent' && item.protocol_step?.includes('M3_M4_RECV')) || item.protocol_step?.includes('M3_M4_DROPPED')) {
                            direction = 'uav-to-zsp';
                            messageType = 'M3/M4';
                          } else if (item.phase === 'initiated' && !item.protocol_step?.includes('RETRY') && item.message_type !== 'RETRY') {
                            direction = 'uav-to-zsp';
                            messageType = '会话建立';
                          } else if (item.phase === 'session_key_established') {
                            direction = 'uav-to-zsp';
                            messageType = '会话密钥建立';
                          } else if (item.session_result === 'success' || item.phase === 'success') {
                            direction = 'uav-to-zsp';
                            messageType = '认证成功';
                          } else if (item.session_result === 'timeout' || item.phase === 'timeout' || item.protocol_step?.includes('RETRY_BUDGET_EXHAUSTED')) {
                            direction = 'uav-to-zsp';
                            messageType = '超时';
                            isTimeout = true;
                            // 当显示超时消息气泡时，将子会话结果标记为超时
                            // 注意：这里只修改子会话的结果，不修改整个认证会话的结果
                            // 认证会话的结果应该基于所有子会话的结果
                          } else if (item.session_result === 'failed' || item.phase === 'failed' || 
                              item.error_reason === 'unknown_pid' || item.error_reason === 'invalid_pid' || item.protocol_step?.includes('PID_MISMATCH') ||
                              item.error_reason === 'decrypt_failed' || item.error_reason === 'decryption_error' || item.protocol_step?.includes('DECRYPT')) {
                            direction = 'zsp-to-uav';
                            if (item.error_reason === 'unknown_pid' || item.error_reason === 'invalid_pid' || item.protocol_step?.includes('PID_MISMATCH')) {
                              messageType = 'PID未知';
                            } else if (item.error_reason === 'decrypt_failed' || item.error_reason === 'decryption_error' || item.protocol_step?.includes('DECRYPT')) {
                              messageType = '无法解密';
                            } else {
                              messageType = '失败';
                            }
                          }
                          
                          // 检测丢包事件
                          if (item.success === false && (item.error_reason?.includes('dropped') || 
                              item.protocol_step?.includes('DROPPED') || item.phase?.includes('dropped'))) {
                            isPacketDrop = true;
                          }
                          
                          // 检测超时事件
                          if (item.phase === 'timeout' || item.is_timeout || item.protocol_step?.includes('RETRY_BUDGET_EXHAUSTED')) {
                            isTimeout = true;
                            messageType = '超时';
                          }
                          
                          // 检测PID未知或无法解密事件
                          let errorReason = null;
                          if (item.error_reason === 'unknown_pid' || item.error_reason === 'invalid_pid' || item.protocol_step?.includes('PID_MISMATCH')) {
                            errorReason = 'PID未知';
                          } else if (item.error_reason === 'decrypt_failed' || item.error_reason === 'decryption_error' || item.protocol_step?.includes('DECRYPT')) {
                            errorReason = '无法解密';
                          } else if (isPacketDrop) {
                            errorReason = '丢包';
                          } else if (isTimeout) {
                            errorReason = '超时';
                          }
                          
                          return (
                            <div key={`${subsessionKey}-${idx}`} className="sequence-item">
                              <div className="sequence-time">{formatNumber(item.sim_time)}s</div>
                              <div className="sequence-message-container">
                                {direction === 'uav-to-zsp' ? (
                                  <div className="message-sender uav-side">
                                    <div className={`message-bubble ${isPacketDrop ? 'packet-drop' : ''} ${isRetry ? 'retry' : ''} ${isTimeout ? 'timeout' : ''}`}>
                                      <div className="message-type">{messageType}</div>
                                      {errorReason && (
                                        <div className="message-note">{errorReason}</div>
                                      )}
                                    </div>
                                    <div className={`message-arrow uav-to-zsp ${isPacketDrop ? 'packet-drop' : ''} ${isRetry ? 'retry' : ''} ${isTimeout ? 'timeout' : ''}`}>
                                      {isPacketDrop && (
                                        <div className="packet-drop-mark">×</div>
                                      )}
                                    </div>
                                  </div>
                                ) : (
                                  <div className="message-sender zsp-side">
                                    <div className={`message-arrow zsp-to-uav ${isPacketDrop ? 'packet-drop' : ''} ${isRetry ? 'retry' : ''} ${isTimeout ? 'timeout' : ''}`}>
                                      {isPacketDrop && (
                                        <div className="packet-drop-mark">×</div>
                                      )}
                                    </div>
                                    <div className={`message-bubble ${isPacketDrop ? 'packet-drop' : ''} ${isRetry ? 'retry' : ''} ${isTimeout ? 'timeout' : ''}`}>
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
                        });
                      };
                      
                      // 按子会话ID排序分组键
                      const sortedSubsessionKeys = Object.keys(subsessionGroups).sort((a, b) => {
                        return parseInt(a) - parseInt(b);
                      });
                      
                      // 翻页功能逻辑
                      const totalSubsessions = sortedSubsessionKeys.length;
                      const currentSubsessionKey = sortedSubsessionKeys[currentSubsessionIndex];
                      const currentSubsessionEvents = subsessionGroups[currentSubsessionKey] || [];
                      
                      // 处理翻页
                      const handlePrevPage = () => {
                        setCurrentSubsessionIndex(prev => (prev > 0 ? prev - 1 : totalSubsessions - 1));
                      };
                      
                      const handleNextPage = () => {
                        setCurrentSubsessionIndex(prev => (prev < totalSubsessions - 1 ? prev + 1 : 0));
                      };
                      
                      // 渲染当前子会话
                      return (
                        <div className="timeline-pagination-container">
                          <div className="timeline-navigation">
                            <button onClick={handlePrevPage} className="nav-btn">
                              ← 上一页
                            </button>
                            <span className="pagination-info">
                              子会话 {currentSubsessionIndex + 1} / {totalSubsessions}
                            </span>
                            <button onClick={handleNextPage} className="nav-btn">
                              下一页 →
                            </button>
                          </div>
                          
                          <div className="subsession-group">
                            <div className="subsession-header">
                              {parseInt(currentSubsessionKey) === 0 ? '初始会话' : `子会话 ${currentSubsessionKey}`}
                            </div>
                            <div className="subsession-sequence-diagram">
                              <div className="sequence-diagram-header">
                                <div className="participant uav">UAV {selectedSession.uav_id}</div>
                                <div className="participant zsp">ZSP {selectedSession.zsp_id}</div>
                              </div>
                              <div className="sequence-diagram-content">
                                {renderSubsessionGroup(currentSubsessionEvents, currentSubsessionKey)}
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })()}
                  </div>
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
