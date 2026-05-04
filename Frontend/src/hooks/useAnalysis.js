import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { API_ENDPOINTS } from '../config/api';
import { parseSessionId } from '../utils/helpers';

export const useAnalysis = (taskId) => {
  const [metrics, setMetrics] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [groupedSessions, setGroupedSessions] = useState({});
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const loadAllData = useCallback(async () => {
    setLoading(true);
    setError(null);
    const t = taskId?.trim();
    const qp = t ? { task_id: t } : {};

    try {
      const results = await Promise.allSettled([
        axios.get(API_ENDPOINTS.metrics.summary, { params: qp }),
        axios.get(API_ENDPOINTS.analysis.sessions, { params: qp }),
        axios.get(API_ENDPOINTS.analysis.events, { params: { limit: 80, ...qp } }),
      ]);

      if (results[0].status === 'fulfilled') {
        setMetrics(results[0].value.data.metrics);
      }

      if (results[1].status === 'fulfilled') {
        const sessionData = results[1].value.data.sessions || [];
        setSessions(sessionData);

        const grouped = sessionData.reduce((acc, session) => {
          const pairKey = `${session.uav_id}-${session.zsp_id}`;

          if (!acc[pairKey]) {
            acc[pairKey] = {
              uavId: session.uav_id,
              zspId: session.zsp_id,
              pairKey: pairKey,
              parentSessions: {}
            };
          }

          const parsed = parseSessionId(session.session_id);
          if (!parsed) {
            if (!acc[pairKey].orphanSessions) {
              acc[pairKey].orphanSessions = [];
            }
            acc[pairKey].orphanSessions.push(session);
            return acc;
          }

          const sessionIdx = parsed.session_idx;
          if (!acc[pairKey].parentSessions[sessionIdx]) {
            acc[pairKey].parentSessions[sessionIdx] = {
              uavId: session.uav_id,
              zspId: session.zsp_id,
              sessionIdx: sessionIdx,
              parentKey: parsed.parentKey,
              sessions: [],
              isParentGroup: true
            };
          }

          acc[pairKey].parentSessions[sessionIdx].sessions.push(session);
          return acc;
        }, {});

        Object.values(grouped).forEach(pairGroup => {
          Object.values(pairGroup.parentSessions || {}).forEach(parentSession => {
            parentSession.sessions.sort((a, b) => {
              const parsedA = parseSessionId(a.session_id);
              const parsedB = parseSessionId(b.session_id);
              if (parsedA && parsedB) {
                return parseInt(parsedA.subsession_idx) - parseInt(parsedB.subsession_idx);
              }
              const timeA = a.start_time || a.sim_time || 0;
              const timeB = b.start_time || b.sim_time || 0;
              return timeA - timeB;
            });
          });

          if (pairGroup.parentSessions) {
            pairGroup.parentSessionsArray = Object.values(pairGroup.parentSessions).sort((a, b) => {
              return parseInt(a.sessionIdx) - parseInt(b.sessionIdx);
            });
          }
        });

        setGroupedSessions(grouped);
      } else {
        setSessions([]);
        setGroupedSessions({});
      }

      if (results[2].status === 'fulfilled') {
        setEvents(results[2].value.data.events || []);
      } else {
        setEvents([]);
      }
    } catch (err) {
      setError('加载数据失败');
      console.error('Failed to load analysis data:', err);
    } finally {
      setLoading(false);
    }
  }, [taskId]);

  const getTimeline = useCallback(async (sessionId) => {
    const t = taskId?.trim();
    const qp = t ? { task_id: t } : {};
    try {
      const response = await axios.get(API_ENDPOINTS.analysis.timeline(sessionId), { params: qp });
      return response.data.diagram;
    } catch (err) {
      throw new Error(err.response?.data?.detail || err.message);
    }
  }, [taskId]);

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 5000);
    return () => clearInterval(interval);
  }, [loadAllData]);

  return {
    metrics,
    sessions,
    groupedSessions,
    events,
    loading,
    error,
    loadAllData,
    getTimeline,
  };
};