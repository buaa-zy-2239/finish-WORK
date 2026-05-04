const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000/api/v1';

export const API_ENDPOINTS = {
  simulation: {
    create: `${API_BASE_URL}/simulation/create`,
    list: `${API_BASE_URL}/simulation/list`,
    run: (taskId) => `${API_BASE_URL}/simulation/run/${taskId}`,
    status: (taskId) => `${API_BASE_URL}/simulation/status/${taskId}`,
    config: (taskId) => `${API_BASE_URL}/simulation/config/${taskId}`,
  },
  metrics: {
    summary: `${API_BASE_URL}/metrics/summary`,
  },
  analysis: {
    sessions: `${API_BASE_URL}/analysis/sessions`,
    events: `${API_BASE_URL}/analysis/events`,
    timeline: (sessionId) => `${API_BASE_URL}/analysis/timeline-diagram/${sessionId}`,
  },
};

export default API_BASE_URL;