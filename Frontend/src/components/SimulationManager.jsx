// Frontend/src/components/SimulationManager.jsx
/**
 * 仿真管理器 - 创建和运行仿真任务
 */

import React, { useState } from 'react';
import axios from 'axios';
import './SimulationManager.css';

const API_BASE = 'http://localhost:8000/api/v1';

export const SimulationManager = () => {
  const [taskName, setTaskName] = useState('');
  const [description, setDescription] = useState('');
  const [duration, setDuration] = useState(30);
  const [loading, setLoading] = useState(false);
  const [tasks, setTasks] = useState([]);
  const [selectedTask, setSelectedTask] = useState(null);

  // UAV 配置
  const [uavs, setUavs] = useState([
    { id: 0, mobility: { type: 'waypoint', waypoints: [[0, [0, 0, 50]], [10, [200, 0, 50]]] } },
    { id: 1, mobility: { type: 'waypoint', waypoints: [[0, [100, 0, 50]], [10, [300, 0, 50]]] } }
  ]);

  // ZSP 配置
  const [zsps, setZsps] = useState([
    { id: 2, position: [0, 0, 100] },
    { id: 3, position: [500, 0, 100] }
  ]);

  // 创建仿真任务
  const handleCreateTask = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axios.post(`${API_BASE}/simulation/create`, {
        name: taskName,
        description,
        duration,
        uavs,
        zsps,
        protocol: 'PMAP',
        channel: { type: 'CSMA', datarate: '100Mbps' }
      });

      if (response.data.success) {
        alert(`✓ 仿真任务创建成功！\n任务ID: ${response.data.task_id}`);
        setTaskName('');
        setDescription('');
        loadTasks();
      }
    } catch (error) {
      alert(`✗ 创建失败: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  // 加载任务列表
  const loadTasks = async () => {
    try {
      const response = await axios.get(`${API_BASE}/simulation/list`);
      setTasks(response.data.tasks);
    } catch (error) {
      console.error('Failed to load tasks:', error);
    }
  };

  // 运行仿真
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

  // 查看任务详情
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
            <label>任务名称：</label>
            <input
              type="text"
              value={taskName}
              onChange={(e) => setTaskName(e.target.value)}
              placeholder="输入仿真任务名称"
              required
            />
          </div>

          <div className="form-group">
            <label>任务描述：</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="输入任务描述"
            />
          </div>

          <div className="form-group">
            <label>仿真时长（秒）：</label>
            <input
              type="number"
              value={duration}
              onChange={(e) => setDuration(parseInt(e.target.value))}
              min="1"
              max="3600"
            />
          </div>

          <button type="submit" disabled={loading}>
            {loading ? '创建中...' : '创建任务'}
          </button>
        </form>
      </div>

      <div className="section tasks-section">
        <h2>📊 仿真任务列表</h2>
        <button onClick={loadTasks} className="refresh-btn">
          刷新列表
        </button>

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
                <td>{task.task_id.substring(0, 15)}...</td>
                <td>{task.task_dir}</td>
                <td>
                  <span className={`status-badge status-${task.status}`}>
                    {task.status}
                  </span>
                </td>
                <td>{new Date(task.created_at).toLocaleString('zh-CN')}</td>
                <td className="action-buttons">
                  {task.status === 'created' && (
                    <button onClick={() => handleRunTask(task.task_id)} className="run-btn">
                      ▶ 运行
                    </button>
                  )}
                  <button onClick={() => handleViewTask(task.task_id)} className="view-btn">
                    👁 查看
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selectedTask && (
        <div className="section task-details-section">
          <h2>📌 任务详情</h2>
          <div className="task-details">
            <p><strong>状态：</strong> {selectedTask.status}</p>
            <p><strong>进度：</strong> {selectedTask.progress}%</p>
            <p><strong>创建时间：</strong> {selectedTask.created_at}</p>
            {selectedTask.started_at && (
              <p><strong>启动时间：</strong> {selectedTask.started_at}</p>
            )}
            {selectedTask.completed_at && (
              <p><strong>完成时间：</strong> {selectedTask.completed_at}</p>
            )}
            <details>
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