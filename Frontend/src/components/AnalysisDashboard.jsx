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
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [taskId, setTaskId] = useState('');

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
      setTimeline(response.data.timeline || []);
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
            {Object.values(groupedSessions).map((group) => (
              <div key={`${group.uavId}-${group.zspId}`} className="session-group">
                <h3>UAV {group.uavId} ↔ ZSP {group.zspId}</h3>
                <table className="sessions-table">
                  <thead>
                    <tr>
                      <th>会话 ID</th>
                      <th>状态</th>
                      <th>触发来源</th>
                      <th>耗时 (s)</th>
                      <th>消息数</th>
                      <th>字节</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {group.sessions.map((session, idx) => (
                      <tr key={session.session_id || idx} className={session.success ? 'success-row' : session.is_timeout ? 'warning-row' : 'error-row'}>
                        <td className="session-id-cell" title={session.session_id}>
                          {(session.session_id || '').slice(0, 12)}
                          {(session.session_id || '').length > 12 ? '…' : ''}
                        </td>
                        <td>
                          <span className={`status-badge ${session.success ? 'success' : session.is_timeout ? 'warning' : 'error'}`}>
                            {session.success ? '成功' : session.is_timeout ? '超时' : '失败'}
                          </span>
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
                          <button onClick={() => handleViewSessionTimeline(session)} className="timeline-btn">
                            时间线
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </div>
        )}
      </div>

      {selectedSession && (
        <div className="timeline-section">
          <h2>
            会话时间线 — UAV {selectedSession.uav_id} → ZSP {selectedSession.zsp_id}
            {selectedSession.session_id ? ` (${selectedSession.session_id.slice(0, 8)}…)` : ''}
          </h2>
          <div className="timeline-meta">
            <span className="trigger-badge" title={selectedSession.trigger_step || ''}>
              触发来源：{formatTriggerLabel(selectedSession.trigger_reason)}
            </span>
          </div>
          {timeline.length === 0 ? (
            <div className="empty-state">
              <p>暂无时间线数据</p>
            </div>
          ) : (
            <div className="timeline">
              {timeline.map((event, idx) => (
                <div key={idx} className="timeline-event">
                  <div className="timeline-time">{Number(event.sim_time).toFixed(4)}s</div>
                  <div className={`timeline-content phase-${event.phase}`}>
                    <strong>{event.phase}</strong>
                    {event.protocol_step && (
                      <span className="msg-type" title="protocol_step">
                        {event.protocol_step}
                      </span>
                    )}
                    {event.message_type && <span className="msg-type">{event.message_type}</span>}
                    {event.payload_size ? <span className="msg-size">{event.payload_size}B</span> : null}
                    {event.auth_session_id && (
                      <span className="msg-size" title={event.auth_session_id}>
                        sid…
                      </span>
                    )}
                    {event.warning_type === 'uplink_loss_injected' && event.message_type && (
                      <span className="msg-type loss-event" title="丢包事件">
                        丢包: {event.message_type}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

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
    </div>
  );
};

export default AnalysisDashboard;
