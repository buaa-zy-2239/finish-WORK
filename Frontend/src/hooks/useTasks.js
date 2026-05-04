import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { API_ENDPOINTS } from '../config/api';

export const useTasks = () => {
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const loadTasks = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get(API_ENDPOINTS.simulation.list);
      setTasks(response.data.tasks || []);
    } catch (err) {
      setError('加载任务失败');
      console.error('Failed to load tasks:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  const createTask = useCallback(async (taskData) => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(API_ENDPOINTS.simulation.create, taskData);
      if (response.data.success) {
        await loadTasks();
        return { success: true, taskId: response.data.task_id };
      }
      return { success: false, error: '创建失败' };
    } catch (err) {
      const message = err.response?.data?.detail || err.message;
      setError(message);
      return { success: false, error: message };
    } finally {
      setLoading(false);
    }
  }, [loadTasks]);

  const runTask = useCallback(async (taskId) => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(API_ENDPOINTS.simulation.run(taskId));
      if (response.data.success) {
        await loadTasks();
        return { success: true };
      }
      return { success: false, error: '启动失败' };
    } catch (err) {
      const message = err.response?.data?.detail || err.message;
      setError(message);
      return { success: false, error: message };
    } finally {
      setLoading(false);
    }
  }, [loadTasks]);

  const getTaskDetail = useCallback(async (taskId) => {
    try {
      const [configResponse, statusResponse] = await Promise.all([
        axios.get(API_ENDPOINTS.simulation.config(taskId)),
        axios.get(API_ENDPOINTS.simulation.status(taskId)),
      ]);
      return {
        ...statusResponse.data,
        config: configResponse.data.config,
      };
    } catch (err) {
      throw new Error(err.response?.data?.detail || err.message);
    }
  }, []);

  useEffect(() => {
    loadTasks();
  }, [loadTasks]);

  return {
    tasks,
    loading,
    error,
    loadTasks,
    createTask,
    runTask,
    getTaskDetail,
  };
};