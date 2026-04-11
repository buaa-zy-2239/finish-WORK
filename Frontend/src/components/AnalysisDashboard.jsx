import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './AnalysisDashboard.css';

const API_BASE = 'http://localhost:8000/api/v1';

export const AnalysisDashboard = () => {
  const [metrics, setMetrics] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [events, setEvents] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadAllData = async () => {
    setLoading(true);
    setError(null);
    try {
      const results = await Promise.allSettled([
        axios.get(`${API_BASE}/metrics/summary`),
        axios.get(`${API_BASE}/analysis/sessions`),
        axios.get(`${API_BASE}/analysis/events?limit=50`)
      ]);

      // 处理metrics
      if (results[0].status === 'fulfilled') {
        setMetrics(results[0].value.data.metrics);
      } else {
        console.error('Failed to load metrics:', results[0].reason);
      }

      // 处理sessions
      if (results[1].status === 'fulfilled') {
        setSessions(results[1].value.data.sessions || []);
      } else {
        console.error('Failed to load sessions:', results[1].reason);
        setSessions([]);
      }

      // 处理events
      if (results[2].status === 'fulfilled') {
        setEvents(results[2].value.data.events || []);
      } else {
        console.error('Failed to load events:', results[2].reason);
        setEvents([]);
      }
    } catch (error) {
      console.error('Failed to load data:', error);
      setError('加载数据失败，请稍后重试');
    } finally {
      setLoading(false);
    }
  };

  const handleViewSessionTimeline = async (session) => {
    try {
      const response = await axios.get(
        `${API_BASE}/analysis/sessions/${session.uav_id}/${session.zsp_id}/timeline`
      );
      setSelectedSession(session);
      setTimeline(response.data.timeline || []);
    } catch (error) {
      console.error('Failed to load timeline:', error);
      alert('加载时间线失败：' + (error.response?.data?.detail || error.message));
    }
  };

  const formatNumber = (num) => {
    if (typeof num !== 'number') return num;
    return num.toFixed(2);
  };

  return (
    <div className="analysis-dashboard">
      {error && (
        <div className="error-banner">
          ⚠️ {error}
        </div>
      )}

      {/* 指标卡 */}
      <div className="metrics-section">
        <h2>🔍 认证协议性能指标</h2>
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
              <h3>消息统计</h3>
              <div className="metric-item">
                <span className="label">总消息数：</span>
                <span className="value">{metrics.messaging?.total_messages || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">平均大小：</span>
                <span className="value">{formatNumber(metrics.messaging?.avg_size_bytes)} bytes</span>
              </div>
              <div className="metric-item">
                <span className="label">总字节：</span>
                <span className="value">{metrics.messaging?.total_bytes || 0} bytes</span>
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
                <span className="label">总错误数：</span>
                <span className="value error">{metrics.errors?.total || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">M1 错误：</span>
                <span className="value">{metrics.errors?.M1_errors || 0}</span>
              </div>
              <div className="metric-item">
                <span className="label">M2 错误：</span>
                <span className="value">{metrics.errors?.M2_errors || 0}</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="loading-placeholder">
            {loading ? '加载中...' : '暂无数据'}
          </div>
        )}
      </div>

      {/* 会话列表 */}
      <div className="sessions-section">
        <h2>📋 认证会话列表</h2>
        <button onClick={loadAllData} className="refresh-btn" disabled={loading}>
          🔄 {loading ? '加载中...' : '刷新数据'}
        </button>

        {sessions.length === 0 ? (
          <div className="empty-state">
            <p>📭 暂无会话数据</p>
            <small>执行仿真后将显示认证会话信息</small>
          </div>
        ) : (
          <table className="sessions-table">
            <thead>
              <tr>
                <th>UAV ID</th>
                <th>ZSP ID</th>
                <th>状态</th>
                <th>耗时 (s)</th>
                <th>消息数</th>
                <th>通信量 (bytes)</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session, idx) => (
                <tr key={idx} className={session.success ? 'success-row' : 'error-row'}>
                  <td>{session.uav_id}</td>
                  <td>{session.zsp_id}</td>
                  <td>
                    <span className={`status-badge ${session.success ? 'success' : 'error'}`}>
                      {session.success ? '✓ 成功' : '✗ 失败'}
                    </span>
                  </td>
                  <td>{formatNumber(session.duration_seconds)}</td>
                  <td>{session.message_count}</td>
                  <td>{(session.message_sizes.M1 || 0) + (session.message_sizes.M2 || 0) + (session.message_sizes.M3_M4 || 0)}</td>
                  <td>
                    <button
                      onClick={() => handleViewSessionTimeline(session)}
                      className="timeline-btn"
                    >
                      📊 时间线
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* 时间线 */}
      {selectedSession && (
        <div className="timeline-section">
          <h2>📈 会话时间线 - UAV{selectedSession.uav_id} → ZSP{selectedSession.zsp_id}</h2>
          {timeline.length === 0 ? (
            <div className="empty-state">
              <p>暂无时间线数据</p>
            </div>
          ) : (
            <div className="timeline">
              {timeline.map((event, idx) => (
                <div key={idx} className="timeline-event">
                  <div className="timeline-time">
                    {event.sim_time.toFixed(4)}s
                  </div>
                  <div className={`timeline-content phase-${event.phase}`}>
                    <strong>{event.phase}</strong>
                    {event.message_type && <span className="msg-type">{event.message_type}</span>}
                    {event.payload_size && <span className="msg-size">{event.payload_size}B</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 最新事件 */}
      <div className="events-section">
        <h2>🔔 最新事件</h2>
        {events.length === 0 ? (
          <div className="empty-state">
            <p>📭 暂无事件</p>
            <small>执行仿真后将显示事件信息</small>
          </div>
        ) : (
          <div className="events-list">
            {events.slice(0, 20).map((event, idx) => (
              <div key={idx} className="event-item">
                <span className="event-time">{event.sim_time.toFixed(4)}s</span>
                <span className="event-type">{event.phase}</span>
                <span className="event-detail">
                  UAV{event.uav_id} → ZSP{event.zsp_id}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default AnalysisDashboard;