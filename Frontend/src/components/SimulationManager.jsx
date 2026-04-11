import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './SimulationManager.css';

const API_BASE = 'http://localhost:8000/api/v1';

export const SimulationManager = () => {
  const [taskName, setTaskName] = useState('');
  const [duration, setDuration] = useState(30);
  const [loading, setLoading] = useState(false);
  const [tasks, setTasks] = useState([]);
  const [selectedTask, setSelectedTask] = useState(null);

  const [uavs] = useState([
    { id: 0, mobility: { type: 'waypoint', waypoints: [[0, [0, 0, 50]], [10, [200, 0, 50]]] } },
    { id: 1, mobility: { type: 'waypoint', waypoints: [[0, [100, 0, 50]], [10, [300, 0, 50]]] } }
  ]);

  const [zsps] = useState([
    { id: 2, position: [0, 0, 100] },
    { id: 3, position: [500, 0, 100] }
  ]);

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
        uavs,
        zsps,
        protocol: 'PMAP',
        channel: { type: 'CSMA', datarate: '100Mbps' }
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

  const handleViewTask = async (taskId) => {
    try {
      const configResponse = await axios.get(`${API_BASE}/simulation/config/${taskId}`);
      const statusResponse = await axios.get(`${API_BASE}/simulation/status/${taskId}`);
      
      setSelectedTask({
        ...statusResponse.data,
        config: configResponse.data.config
      });
    } catch (error) {
      alert(`✗ 获取任务详情失败: ${error.message}`);
    }
  };

  return (
    <div className="simulation-manager">
      <div className="section create-section">
        <h2>📋 创建新仿真任务</h2>
        <form onSubmit={handleCreateTask}>
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
            <label>仿真时长：</label>
            <div className="duration-input">
              <input
                type="number"
                value={duration}
                onChange={(e) => setDuration(parseInt(e.target.value))}
                min="1"
                max="3600"
              />
              <span className="unit">秒</span>
            </div>
          </div>

          <div className="form-info">
            <p>🎯 <strong>默认配置：</strong></p>
            <ul>
              <li>协议：PMAP</li>
              <li>UAV 节点：2个</li>
              <li>ZSP 节点：2个</li>
              <li>通道：CSMA / 100Mbps</li>
            </ul>
          </div>

          <button type="submit" disabled={loading} className="create-btn">
            {loading ? '创建中...' : '✨ 创建任务'}
          </button>
        </form>
      </div>

      <div className="section tasks-section">
        <h2>📊 仿真任务列表</h2>
        <button onClick={loadTasks} className="refresh-btn">
          🔄 刷新列表
        </button>

        {tasks.length === 0 ? (
          <div className="empty-state">
            <p>📭 暂无任务</p>
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
                  <td className="task-id">{task.task_id.substring(0, 15)}...</td>
                  <td>{task.name || '未命名任务'}</td>
                  <td>
                    <span className={`status-badge status-${task.status}`}>
                      {task.status === 'created' && '✎ 已创建'}
                      {task.status === 'running' && '⟳ 运行中'}
                      {task.status === 'completed' && '✓ 已完成'}
                      {task.status === 'failed' && '✗ 失败'}
                    </span>
                  </td>
                  <td className="time">{new Date(task.created_at).toLocaleString('zh-CN')}</td>
                  <td className="action-buttons">
                    {task.status === 'created' && (
                      <button onClick={() => handleRunTask(task.task_id)} className="run-btn">
                        ▶ 运行
                      </button>
                    )}
                    <button onClick={() => handleViewTask(task.task_id)} className="view-btn">
                      👁 详情
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
          <h2>📌 任务详情</h2>
          <div className="task-details">
            <div className="detail-row">
              <span className="label">状态：</span>
              <span className={`status-badge status-${selectedTask.status}`}>
                {selectedTask.status === 'created' && '✎ 已创建'}
                {selectedTask.status === 'running' && '⟳ 运行中'}
                {selectedTask.status === 'completed' && '✓ 已完成'}
                {selectedTask.status === 'failed' && '✗ 失败'}
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
              <summary>📋 配置详情</summary>
              <pre>{JSON.stringify(selectedTask.config, null, 2)}</pre>
            </details>
          </div>
        </div>
      )}
    </div>
  );
};

export default SimulationManager;