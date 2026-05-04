export const PROTOCOL_OPTIONS = [
  { value: 'PMAP', label: 'PMAP（经典：发完 M3/M4 即本地换 PID）' },
  { value: 'PMAP_ACK', label: 'PMAP_ACK（会话冗余：收 ZSP 的 D2Z_ACK 后才换 PID）' },
  { value: 'STATIC_BASELINE', label: 'STATIC_BASELINE（静态/预共享身份基线协议）' },
  { value: 'RLBA_UAV', label: 'RLBA_UAV（三方 AKA 的平台映射版对照协议）' },
  { value: 'RLBA_3WAY', label: 'RLBA_3WAY（完整三方 AKA 协议）' },
];

export const USER_COUNT_OPTIONS = [1, 5, 10, 20];

export const BASELINE_SCENARIO_IDS = new Set([
  'baseline_d2z',
  'pmap_ack_baseline',
  'pmap_ack_attack_drop_ack',
]);

export const SWARM_SIZE_OPTIONS = [10, 30, 50, 100];

export const DENSITY_OPTIONS = [
  { value: 1, label: 'low (1 UAV/km²)' },
  { value: 10, label: 'medium (10 UAV/km²)' },
  { value: 50, label: 'high (50 UAV/km²)' }
];

export const GM3D_STRESS_OPTIONS = [
  { value: 'hover', label: '悬停 (1±0.5 m/s)' },
  { value: 'conservative', label: '保守 (3±2 m/s)' },
  { value: 'nominal', label: '标准 (5±5 m/s)' },
  { value: 'aggressive', label: '激进 (12±7 m/s)' },
  { value: 'high_speed', label: '高速 (18±8 m/s)' }
];

export const CHANNEL_MODEL_OPTIONS = [
  { value: 'friis_log_distance', label: 'Friis Log-Distance (默认)' },
  { value: 'nakagami', label: 'Nakagami 多径衰落' },
  { value: 'range', label: 'Range 范围模型' },
  { value: '3gpp_uav', label: '3GPP UAV (多模型组合)' },
  { value: '3gpp_native', label: '3GPP Native (ns-3 内置 TR 38.901)' }
];

export const THREE_GPP_SCENARIO_OPTIONS = [
  { value: 'uma', label: 'UMA (Urban Macro 城市宏站)' },
  { value: 'umi', label: 'UMI (Urban Micro Street Canyon 城市微站)' },
  { value: 'rma', label: 'RMA (Rural Macro 农村宏站)' }
];

export const CARRIER_FREQUENCY_OPTIONS = [
  { value: 2.4e9, label: '2.4 GHz' },
  { value: 5.0e9, label: '5.0 GHz' },
  { value: 5.9e9, label: '5.9 GHz (C-V2X 常用)' },
  { value: 6.0e9, label: '6.0 GHz' }
];

export const LOSS_RATE_OPTIONS = [
  { value: 0.0, label: '0% (无丢包)' },
  { value: 0.05, label: '5% (轻微)' },
  { value: 0.1, label: '10% (轻度)' },
  { value: 0.2, label: '20% (中度)' },
  { value: 0.3, label: '30% (重度)' },
  { value: 0.5, label: '50% (严重)' }
];

export const THREE_GPP_ENVIRONMENT_PRESETS = {
  uma: {
    name: 'Urban Macro',
    description: '城市宏站环境，适合郊区或城市边缘的高架基站',
    typical_height_range: '25-150m',
    cell_radius: '500-1000m',
    recommended_uav_altitude: '40-120m',
    pathloss_exponent: 3.67,
    los_probability_params: { h_bs: 35, h_ut: 1.5 }
  },
  umi: {
    name: 'Urban Micro',
    description: '城市微站环境，适合街道峡谷场景的地面或低高度基站',
    typical_height_range: '10-25m',
    cell_radius: '100-500m',
    recommended_uav_altitude: '20-50m',
    pathloss_exponent: 4.03,
    los_probability_params: { h_bs: 10, h_ut: 1.5 }
  },
  rma: {
    name: 'Rural Macro',
    description: '农村宏站环境，适合开阔地区的长距离通信',
    typical_height_range: '25-150m',
    cell_radius: '1000-5000m',
    recommended_uav_altitude: '50-200m',
    pathloss_exponent: 3.03,
    los_probability_params: { h_bs: 45, h_ut: 1.5 }
  }
};

export const PROTOCOL_DETAILS = {
  PMAP: {
    name: 'PMAP',
    description: '经典PMAP协议：发完 M3/M4 即本地换 PID',
    flow: [
      'UAV → ZSP: M1 (认证请求)',
      'ZSP → UAV: M2 (挑战)',
      'UAV → ZSP: M3/M4 (响应)',
      'UAV: 本地更新 PID'
    ],
    features: [
      '轻量级认证流程',
      '快速PID更新',
      '适合低延迟场景',
      '基本的安全保障'
    ],
    configs: []
  },
  PMAP_ACK: {
    name: 'PMAP_ACK',
    description: 'PMAP_ACK协议：收 ZSP 的 D2Z_ACK 后才换 PID',
    flow: [
      'UAV → ZSP: M1 (认证请求)',
      'ZSP → UAV: M2 (挑战)',
      'UAV → ZSP: M3/M4 (响应)',
      'ZSP → UAV: D2Z_ACK (确认)',
      'UAV: 收到ACK后更新 PID'
    ],
    features: [
      '会话冗余机制',
      '更可靠的认证确认',
      '适合高丢包率环境',
      '增强的安全性'
    ],
    configs: []
  },
  STATIC_BASELINE: {
    name: 'STATIC_BASELINE',
    description: '静态/预共享身份基线协议',
    flow: [
      'UAV → ZSP: 认证请求 (静态身份)',
      'ZSP → UAV: 认证响应',
      'UAV: 使用预共享密钥'
    ],
    features: [
      '最简单的认证方式',
      '低计算开销',
      '适合静态环境',
      '作为性能基线'
    ],
    configs: []
  },
  RLBA_UAV: {
    name: 'RLBA_UAV',
    description: '三方 AKA 的平台映射版对照协议',
    flow: [
      'UAV → ZSP: M1 (认证请求)',
      'ZSP → UAV: M2 (挑战)',
      'UAV → ZSP: M3 (响应)',
      'ZSP → UAV: SUCCESS (确认)'
    ],
    features: [
      '基于区块链的认证',
      'PUF技术增强安全性',
      '轻量级设计',
      '适合资源受限设备'
    ],
    configs: []
  },
  RLBA_3WAY: {
    name: 'RLBA_3WAY',
    description: '完整三方 AKA 协议',
    flow: [
      'User → GSS: USER_REQUEST (认证请求)',
      'GSS → UAV: GSS_TO_UAV (挑战)',
      'UAV → GSS: UAV_TO_GSS (响应)',
      'GSS → User: GSS_TO_USER (认证响应)',
      'User → GSS: USER_CONFIRM (确认)',
      'GSS → UAV: SUCCESS (成功消息)'
    ],
    features: [
      '完整的三方认证',
      '基于区块链的记录',
      'PUF技术增强安全性',
      '支持用户-无人机-地面站三方通信'
    ],
    configs: ['userCount']
  }
};