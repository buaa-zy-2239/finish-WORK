Math.seedrandom = function(seed) {
  let s = seed % 2147483647;
  if (s <= 0) s += 214748363;
  return function() {
    s = s * 16807 % 2147483647;
    return (s - 1) / 2147483646;
  };
};

export const estimateLinkLifetime = (motionMode, nUavs, density) => {
  const baseLifetime = 30.0;

  const mobilityFactor = {
    'trace_dataset': 1.0,
    'task_random': 0.7,
    'gauss_markov_3d': 0.5,
  }[motionMode] || 0.8;

  const densityFactor = density > 0 ? Math.min(2.0, Math.max(0.5, 10.0 / density)) : 1.0;
  const scaleFactor = 1.0 / (1.0 + (nUavs / 200));

  return Math.round(baseLifetime * mobilityFactor * densityFactor * scaleFactor * 10) / 10;
};

export const estimateHandoverRate = (nZsps, nUavs, density) => {
  if (nZsps <= 1) {
    return 0.0;
  }

  const uavsPerZsp = nUavs / nZsps;
  let coverageRadiusM = 1000;

  if (density > 0) {
    const areaPerZspKm2 = uavsPerZsp / density;
    coverageRadiusM = Math.sqrt(areaPerZspKm2) * 500;
  }

  const avgSpeedMps = 15.0;
  const boundaryWidthM = 100;
  const crossingTimeS = (coverageRadiusM * 2) / avgSpeedMps;
  const handoverProb = boundaryWidthM / (coverageRadiusM * 2);
  const handoverPerMin = (60.0 / crossingTimeS) * handoverProb;

  return Math.round(handoverPerMin * 100) / 100;
};

export const classifyTopologyDynamicity = (motionMode, nUavs, density) => {
  const linkLifetime = estimateLinkLifetime(motionMode, nUavs, density);
  const linkChangeRate = 1.0 / linkLifetime;
  const normalizedRate = linkChangeRate / Math.max(1, nUavs / 10);

  if (normalizedRate < 0.02) {
    return "low";
  } else if (normalizedRate < 0.1) {
    return "medium";
  } else {
    return "high";
  }
};

export const parseSessionId = (sessionId) => {
  if (!sessionId) return null;
  const parts = sessionId.split('_');
  if (parts.length >= 4 && parts[0] === 'session') {
    const uav_id = parts[1];
    const zsp_id = parts[2];
    const session_idx = parts[3];
    const subsession_idx = parts[4] || '0';
    return {
      uav_id,
      zsp_id,
      session_idx,
      subsession_idx,
      parentKey: `${uav_id}-${zsp_id}-${session_idx}`,
      fullId: sessionId
    };
  }
  return null;
};

export const formatNumber = (num) => {
  if (typeof num !== 'number' || Number.isNaN(num)) return num;
  return num.toFixed(2);
};

export const formatTriggerLabel = (trigger) => {
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

export const copyToClipboard = async (text) => {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      return true;
    }
  } catch (err) {
    console.error('Copy failed:', err);
    return false;
  }
};