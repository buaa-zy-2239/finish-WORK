import { estimateLinkLifetime, estimateHandoverRate, classifyTopologyDynamicity } from './helpers';
import { THREE_GPP_ENVIRONMENT_PRESETS } from '../constants';

const createMobilityStressScenario = (size, density, stressLevel, g3ppScenario = 'uma', carrierFreq = 5.9e9) => {
    const stressParams = {
        hover: { alpha: 0.98, mean_speed_mps: 1.0, speed_std_mps: 0.5, altitude_std_m: 8.0 },
        conservative: { alpha: 0.9, mean_speed_mps: 3.0, speed_std_mps: 2.0, altitude_std_m: 12.0 },
        nominal: { alpha: 0.8, mean_speed_mps: 5.0, speed_std_mps: 4.0, altitude_std_m: 18.0 },
        aggressive: { alpha: 0.6, mean_speed_mps: 10.0, speed_std_mps: 6.0, altitude_std_m: 25.0 },
        high_speed: { alpha: 0.4, mean_speed_mps: 15.0, speed_std_mps: 7.0, altitude_std_m: 30.0 }
    };

    const params = stressParams[stressLevel] || stressParams.nominal;
    const envConfig = THREE_GPP_ENVIRONMENT_PRESETS[g3ppScenario] || THREE_GPP_ENVIRONMENT_PRESETS.uma;

    let area_side_m = 1000.0;
    if (density > 0) {
        const area_km2 = size / density;
        area_side_m = Math.sqrt(area_km2) * 1000;
    }

    const recommendedAltRange = envConfig.recommended_uav_altitude.split('-').map(v => parseInt(v));
    const minAlt = recommendedAltRange[0] || 40;
    const maxAlt = recommendedAltRange[1] || 120;

    const uavs = Array.from({ length: size }, (_, idx) => {
        const seed = 20260417 + idx;
        const random = new Math.seedrandom(seed);
        const initial_distance = random() * 60 + 30;  // 更近的初始距离 30-90m
        const initial_angle = random() * Math.PI * 2;
        const initial_x = initial_distance * Math.cos(initial_angle);
        const initial_y = initial_distance * Math.sin(initial_angle);
        const mean_altitude = (minAlt + maxAlt) / 2;
        const altitude_range = maxAlt - minAlt;
        const initial_z = mean_altitude + (random() * altitude_range - altitude_range / 2);

    return {
      id: idx,
      mobility: {
        type: 'gauss_markov_3d',
        seed: seed,
        alpha: params.alpha,
        mean_speed_mps: params.mean_speed_mps,
        speed_std_mps: params.speed_std_mps,
        mean_altitude_m: mean_altitude,
        altitude_std_m: params.altitude_std_m,
        area_size_x: 400.0,  // 更小的活动区域
        area_size_y: 400.0,
        min_altitude_m: minAlt,
        max_altitude_m: maxAlt,
        initial_position: [Math.round(initial_x * 100) / 100, Math.round(initial_y * 100) / 100, Math.round(initial_z * 100) / 100],
        initial_velocity: [
          Math.round((random() * 2 - 1) * params.mean_speed_mps * 0.8 * 100) / 100,  // 减小初始速度方差
          Math.round((random() * 2 - 1) * params.mean_speed_mps * 0.8 * 100) / 100,
          Math.round((random() * 2 - 1) * 1.0 * 100) / 100  // 更小的垂直速度
        ],
        position_update_interval_s: 0.1,
        cluster_behavior: {
          enabled: size > 10,
          cluster_id: Math.floor(idx / Math.max(1, Math.floor(size / 5))),
          cohesion_weight: 0.3,
          separation_weight: 0.5,
          alignment_weight: 0.2,
        },
      },
      auth_trigger: {
        initial_on_connect: false,
        time_offsets_s: [5, 20, 35, 50],
        allow_reauth: true
      },
      link_state: {
        comm_range_m: 800,
        zsp_handover: {
          enabled: size > 25,
          rssi_threshold_dbm: -85,
          hysteresis_db: 5,
          min_dwell_time_s: 2.0,
          handover_delay_s: 0.5,
          reauth_after_handover: true,
        },
        uplink_burst_loss_model: {
          enabled: true,
          p_good_to_bad: 0.02,
          p_bad_to_good: 0.25,
          loss_good: 0.01,
          loss_bad: 0.75,
        },
      }
    };
  });

  let zsps = [];
  if (size > 25) {
    const n_zsps = Math.max(1, Math.ceil(size / 25));
    const grid_size = Math.ceil(Math.sqrt(n_zsps));
    const spacing_m = area_side_m / (grid_size + 1);

    for (let i = 0; i < n_zsps; i++) {
      const row = Math.floor(i / grid_size);
      const col = i % grid_size;
      const x = (col + 1) * spacing_m - area_side_m / 2;
      const y = (row + 1) * spacing_m - area_side_m / 2;
      const zspHeight = envConfig.typical_height_range ? parseInt(envConfig.typical_height_range.split('-')[0]) : 25;
      zsps.push({
        id: size + 1 + i,
        position: [Math.round(x * 10) / 10, Math.round(y * 10) / 10, zspHeight]
      });
    }
  } else {
    const zspHeight = envConfig.typical_height_range ? parseInt(envConfig.typical_height_range.split('-')[0]) : 25;
    zsps = [{ id: size + 1, position: [0, 0, zspHeight] }];
  }

  let base_duration = 65.0;
  if (size > 30) {
    base_duration = 95.0;
  }

  return {
    id: 'mobility_stress_test',
    label: `机动应力测试 (${stressLevel})`,
    description: `测试 ${stressLevel} 机动性档位下的认证协议性能，网络规模 ${size} UAV，密度 ${density} UAV/km²，3GPP ${g3ppScenario.toUpperCase()} 环境`,
    duration: base_duration,
    uavs,
    zsps,
    channel: {
      type: 'WiFi',
      datarate: 'ErpOfdmRate6Mbps',
      loss_model: '3gpp_native',
      scenario_type: g3ppScenario,
      carrier_freq_hz: carrierFreq,
      enable_shadowing: true
    },
    security_profile: {
      adversary: 'none',
      attack_model: {
        downlink_loss_rate: 0.0,
        d2z_ack_timeout_s: 1.5,
        max_d2z_attempts: 2,
        desync_template: '',
        desync_experiment_enabled: false,
        desync_multi_round: false,
        desync_boundary_recovery: false,
        desync_attack_every_round: false,
        desync_attack_min_completed_sessions: 0,
        desync_attack_max_completed_sessions: null,
        retry_d2z_after_intercept_s: 2.0,
        downlink_burst_loss_model: {
          enabled: true,
          p_good_to_bad: 0.02,
          p_bad_to_good: 0.25,
          loss_good: 0.01,
          loss_bad: 0.75,
        },
      },
    },
    defaultProtocol: 'PMAP_ACK',
    supportsSwarmSize: true,
    supportsDensity: true,
    supportsGM3DStress: true,
    supports3GPPScenario: true,
    stageTag: '机动应力实验',
    scenarioNotes: [
      'Gauss-Markov 3D 移动模型 + 3GPP UAV 信道模型',
      `网络规模：${size} UAV`,
      `密度：${density} UAV/km²`,
      `机动性档位：${stressLevel}`,
      `3GPP环境：${g3ppScenario.toUpperCase()} (${envConfig.name})`,
      `载波频率：${(carrierFreq / 1e9).toFixed(1)} GHz`,
      `ZSP数量：${zsps.length}`,
      '用于主实验B子实验C：机动性敏感性 + 3GPP环境测试'
    ],
    triggerSummary: '时间触发认证 + 自动重认证',
    scenarioProfile: {
      experiment_track: 'main_exp_b',
      sub_experiment: 'mobility_sensitivity_3gpp',
      swarm_size: size,
      density: density,
      gm3d_stress: stressLevel,
      g3pp_scenario: g3ppScenario,
      carrier_freq_hz: carrierFreq,
      zsp_count: zsps.length,
      topology_dynamics: {
        expected_link_lifetime_s: estimateLinkLifetime('gauss_markov_3d', size, density),
        expected_handover_rate_per_min: zsps.length > 1 ? estimateHandoverRate(zsps.length, size, density) : 0,
        topology_change_classification: classifyTopologyDynamicity('gauss_markov_3d', size, density),
      },
    }
  };
};

export const SCENARIOS = [
  {
    id: 'mobility_stress_test',
    label: '机动应力测试',
    description: '测试不同机动性档位下的认证协议性能，支持调整网络规模、密度、GM3D应力档位和3GPP环境',
    duration: 60,
    channel: {
      type: 'WiFi',
      datarate: 'ErpOfdmRate6Mbps',
      loss_model: '3gpp_native',
      scenario_type: 'uma',
      carrier_freq_hz: 5.9e9,
      enable_shadowing: true
    },
    uavs: [
      {
        id: 0,
        mobility: {
          type: 'gauss_markov_3d',
          seed: 20260417,
          alpha: 0.7,
          mean_speed_mps: 5.0,
          speed_std_mps: 5.0,
          mean_altitude_m: 80.0,
          altitude_std_m: 20.0,
          area_size_x: 600.0,
          area_size_y: 600.0,
          min_altitude_m: 40.0,
          max_altitude_m: 120.0,
          initial_position: [0, 0, 80.0],
          initial_velocity: [1.0, 2.0, 0.5],
          position_update_interval_s: 0.1
        },
        auth_trigger: {
          initial_on_connect: false,
          time_offsets_s: [5, 20, 35, 50],
          allow_reauth: true
        },
        link_state: {
          comm_range_m: 500
        }
      },
      {
        id: 1,
        mobility: {
          type: 'gauss_markov_3d',
          seed: 20260418,
          alpha: 0.7,
          mean_speed_mps: 5.0,
          speed_std_mps: 5.0,
          mean_altitude_m: 80.0,
          altitude_std_m: 20.0,
          area_size_x: 600.0,
          area_size_y: 600.0,
          min_altitude_m: 40.0,
          max_altitude_m: 120.0,
          initial_position: [100, 50, 75.0],
          initial_velocity: [-1.5, 1.0, -0.3],
          position_update_interval_s: 0.1
        },
        auth_trigger: {
          initial_on_connect: false,
          time_offsets_s: [7, 22, 37, 52],
          allow_reauth: true
        },
        link_state: {
          comm_range_m: 500
        }
      }
    ],
    zsps: [
      { id: 2, position: [0, 0, 25] }
    ],
    security_profile: { adversary: 'none' },
    defaultProtocol: 'PMAP_ACK',
    supportsSwarmSize: true,
    supportsDensity: true,
    supportsGM3DStress: true,
    supports3GPPScenario: true,
    stageTag: '机动应力实验',
    scenarioNotes: [
      'Gauss-Markov 3D 移动模型 + 3GPP UAV 信道模型',
      '支持调整网络规模：10/30/50/100 UAV',
      '支持调整密度：1/10/50 UAV/km²',
      '支持调整机动性档位：hover/conservative/nominal/aggressive/high_speed',
      '支持调整3GPP环境：uma/umi/rma',
      '支持调整载波频率：2.4/5.0/5.9/6.0 GHz',
      '用于主实验B子实验C：机动性敏感性 + 3GPP环境测试'
    ],
    triggerSummary: '时间触发认证 + 自动重认证',
    scenarioProfile: {
      experiment_track: 'main_exp_b',
      sub_experiment: 'mobility_sensitivity_3gpp',
      swarm_sizes: [10, 30, 50, 100],
      densities: [1, 10, 50],
      gm3d_stress_levels: ['hover', 'conservative', 'nominal', 'aggressive', 'high_speed'],
      g3pp_scenarios: ['uma', 'umi', 'rma'],
      carrier_freqs: [2.4e9, 5.0e9, 5.9e9, 6.0e9]
    }
  },
  {
    id: 'cross_region_flight',
    label: '跨区域飞行',
    description: '测试无人机从一个区域飞行到另一个区域，在不同ZSP之间切换认证的性能',
    duration: 100,
    uavs: [
      {
        id: 0,
        mobility: {
          type: 'transit',
          start: [-500, 0, 100],
          end: [500, 0, 100],
          speed_mps: 8.0
        },
        auth_trigger: {
          initial_on_connect: true,
          allow_reauth: true,
          on_handover: true,
          handover_delay_s: 0.5
        },
        link_state: {
          comm_range_m: 500,
          zsp_handover: {
            enabled: true,
            rssi_threshold_dbm: -95,
            hysteresis_db: 5,
            min_dwell_time_s: 2.0,
            handover_delay_s: 0.5,
            reauth_after_handover: true
          }
        }
      }
    ],
    zsps: [
      { id: 1, position: [-200, 0, 100] },
      { id: 2, position: [200, 0, 100] }
    ],
    security_profile: { 
      adversary: 'none',
      attack_model: {
        d2z_ack_timeout_s: 5.0,
        max_d2z_attempts: 3,
        d2z_retry_delay_s: 1.0
      }
    },
    defaultProtocol: 'PMAP_ACK',
    stageTag: '跨区域实验',
    scenarioNotes: [
      'Transit移动模型',
      '从左区域飞行到右区域',
      '两个ZSP部署',
      '支持ZSP切换认证',
      '用于测试跨区域认证性能'
    ],
    triggerSummary: '连接触发认证 + 切换触发认证',
    scenarioProfile: {
      experiment_track: 'real_world_scenarios',
      sub_experiment: 'cross_region_flight'
    }
  },
  {
    id: 'uplink_loss_test',
    label: '上行丢包测试',
    description: '测试上行链路（UAV→ZSP）丢包对认证协议性能的影响',
    duration: 55,
    uavs: [
      {
        id: 0,
        mobility: {
          type: 'gauss_markov_3d',
          seed: 20260417,
          alpha: 0.8,
          mean_speed_mps: 5.0,
          speed_std_mps: 4.0,
          mean_altitude_m: 80,
          altitude_std_m: 15,
          area_size_x: 300,
          area_size_y: 300,
          min_altitude_m: 50,
          max_altitude_m: 120,
          initial_position: [50, 30, 80],
          initial_velocity: [1.0, 2.0, 0.5],
          position_update_interval_s: 0.1
        },
        auth_trigger: {
          initial_on_connect: false,
          time_offsets_s: [5, 15, 25, 35, 45],
          allow_reauth: true
        },
        link_state: {
          comm_range_m: 500,
          uplink_burst_loss_model: {
            enabled: true,
            p_good_to_bad: 0.03,
            p_bad_to_good: 0.3,
            loss_good: 0.01,
            loss_bad: 0.8
          }
        }
      },
      {
        id: 1,
        mobility: {
          type: 'gauss_markov_3d',
          seed: 20260418,
          alpha: 0.8,
          mean_speed_mps: 5.0,
          speed_std_mps: 4.0,
          mean_altitude_m: 80,
          altitude_std_m: 15,
          area_size_x: 300,
          area_size_y: 300,
          min_altitude_m: 50,
          max_altitude_m: 120,
          initial_position: [-40, 60, 75],
          initial_velocity: [-1.5, 1.0, -0.3],
          position_update_interval_s: 0.1
        },
        auth_trigger: {
          initial_on_connect: false,
          time_offsets_s: [7, 17, 27, 37, 47],
          allow_reauth: true
        },
        link_state: {
          comm_range_m: 500,
          uplink_burst_loss_model: {
            enabled: true,
            p_good_to_bad: 0.03,
            p_bad_to_good: 0.3,
            loss_good: 0.01,
            loss_bad: 0.8
          }
        }
      }
    ],
    zsps: [
      { id: 2, position: [0, 0, 25] }
    ],
    channel: {
      type: 'WiFi',
      datarate: 'ErpOfdmRate6Mbps',
      loss_model: '3gpp_native',
      scenario_type: 'rma',
      carrier_freq_hz: 2.4e9,
      enable_shadowing: true
    },
    security_profile: {
      adversary: 'none',
      attack_model: {
        uplink_loss_rate: 0.1,
        d2z_ack_timeout_s: 2.0,
        max_d2z_attempts: 3,
        desync_template: '',
        desync_experiment_enabled: false,
        desync_multi_round: false,
        desync_boundary_recovery: false,
        desync_attack_every_round: false,
        desync_attack_min_completed_sessions: 0,
        desync_attack_max_completed_sessions: null,
        retry_d2z_after_intercept_s: 2.0,
        downlink_burst_loss_model: {
          enabled: false
        }
      }
    },
    defaultProtocol: 'PMAP_ACK',
    supportsSwarmSize: true,
    supportsLossRate: true,
    stageTag: '丢包测试',
    scenarioNotes: [
      'Gauss-Markov 3D 移动模型',
      '支持调整网络规模：5/10/20 UAV',
      '支持调整丢包率：0%/5%/10%/20%/30%/50%',
      '支持调整机动性档位：hover/conservative/nominal/aggressive/high_speed',
      '用于测试上行链路丢包对协议的影响'
    ],
    triggerSummary: '时间触发认证 + 自动重认证',
    scenarioProfile: {
      experiment_track: 'link_quality_tests',
      sub_experiment: 'uplink_packet_loss',
      swarm_sizes: [5, 10, 20],
      loss_rates: [0, 0.05, 0.1, 0.2, 0.3, 0.5],
      gm3d_stress_levels: ['hover', 'conservative', 'nominal', 'aggressive', 'high_speed']
    }
  },
  {
    id: 'downlink_loss_test',
    label: '下行丢包测试',
    description: '测试下行链路（ZSP→UAV）丢包对认证协议性能的影响',
    duration: 55,
    uavs: [
      {
        id: 0,
        mobility: {
          type: 'gauss_markov_3d',
          seed: 20260417,
          alpha: 0.8,
          mean_speed_mps: 5.0,
          speed_std_mps: 4.0,
          mean_altitude_m: 80,
          altitude_std_m: 15,
          area_size_x: 300,
          area_size_y: 300,
          min_altitude_m: 50,
          max_altitude_m: 120,
          initial_position: [50, 30, 80],
          initial_velocity: [1.0, 2.0, 0.5],
          position_update_interval_s: 0.1
        },
        auth_trigger: {
          initial_on_connect: false,
          time_offsets_s: [5, 15, 25, 35, 45],
          allow_reauth: true
        },
        link_state: {
          comm_range_m: 500
        }
      },
      {
        id: 1,
        mobility: {
          type: 'gauss_markov_3d',
          seed: 20260418,
          alpha: 0.8,
          mean_speed_mps: 5.0,
          speed_std_mps: 4.0,
          mean_altitude_m: 80,
          altitude_std_m: 15,
          area_size_x: 300,
          area_size_y: 300,
          min_altitude_m: 50,
          max_altitude_m: 120,
          initial_position: [-40, 60, 75],
          initial_velocity: [-1.5, 1.0, -0.3],
          position_update_interval_s: 0.1
        },
        auth_trigger: {
          initial_on_connect: false,
          time_offsets_s: [7, 17, 27, 37, 47],
          allow_reauth: true
        },
        link_state: {
          comm_range_m: 500
        }
      }
    ],
    zsps: [
      { id: 2, position: [0, 0, 25] }
    ],
    channel: {
      type: 'WiFi',
      datarate: 'ErpOfdmRate6Mbps',
      loss_model: '3gpp_native',
      scenario_type: 'rma',
      carrier_freq_hz: 2.4e9,
      enable_shadowing: true
    },
    security_profile: {
      adversary: 'none',
      attack_model: {
        downlink_loss_rate: 0.1,
        d2z_ack_timeout_s: 2.0,
        max_d2z_attempts: 3,
        desync_template: '',
        desync_experiment_enabled: false,
        desync_multi_round: false,
        desync_boundary_recovery: false,
        desync_attack_every_round: false,
        desync_attack_min_completed_sessions: 0,
        desync_attack_max_completed_sessions: null,
        retry_d2z_after_intercept_s: 2.0,
        downlink_burst_loss_model: {
          enabled: true,
          p_good_to_bad: 0.03,
          p_bad_to_good: 0.3,
          loss_good: 0.01,
          loss_bad: 0.8
        }
      }
    },
    defaultProtocol: 'PMAP_ACK',
    supportsSwarmSize: true,
    supportsLossRate: true,
    stageTag: '丢包测试',
    scenarioNotes: [
      'Gauss-Markov 3D 移动模型',
      '支持调整网络规模：5/10/20 UAV',
      '支持调整丢包率：0%/5%/10%/20%/30%/50%',
      '支持调整机动性档位：hover/conservative/nominal/aggressive/high_speed',
      '用于测试下行链路丢包对协议的影响'
    ],
    triggerSummary: '时间触发认证 + 自动重认证',
    scenarioProfile: {
      experiment_track: 'link_quality_tests',
      sub_experiment: 'downlink_packet_loss',
      swarm_sizes: [5, 10, 20],
      loss_rates: [0, 0.05, 0.1, 0.2, 0.3, 0.5],
      gm3d_stress_levels: ['hover', 'conservative', 'nominal', 'aggressive', 'high_speed']
    }
  },
];

export { createMobilityStressScenario, createUplinkLossTestScenario, createDownlinkLossTestScenario };

const createUplinkLossTestScenario = (size = 5, lossRate = 0.1, mobilityStress = 'nominal') => {
  const stressParams = {
    hover: { alpha: 0.98, mean_speed_mps: 1.0, speed_std_mps: 0.5 },
    conservative: { alpha: 0.9, mean_speed_mps: 3.0, speed_std_mps: 2.0 },
    nominal: { alpha: 0.8, mean_speed_mps: 5.0, speed_std_mps: 4.0 },
    aggressive: { alpha: 0.6, mean_speed_mps: 10.0, speed_std_mps: 6.0 },
    high_speed: { alpha: 0.4, mean_speed_mps: 15.0, speed_std_mps: 7.0 }
  };

  const params = stressParams[mobilityStress] || stressParams.nominal;

  const uavs = Array.from({ length: size }, (_, idx) => {
    const seed = 20260417 + idx;
    const random = new Math.seedrandom(seed);
    const initial_distance = random() * 80 + 40;
    const initial_angle = random() * Math.PI * 2;
    const initial_x = initial_distance * Math.cos(initial_angle);
    const initial_y = initial_distance * Math.sin(initial_angle);
    const initial_z = 80 + (random() * 40 - 20);

    return {
      id: idx,
      mobility: {
        type: 'gauss_markov_3d',
        seed: seed,
        alpha: params.alpha,
        mean_speed_mps: params.mean_speed_mps,
        speed_std_mps: params.speed_std_mps,
        mean_altitude_m: 80,
        altitude_std_m: 15,
        area_size_x: 300,
        area_size_y: 300,
        min_altitude_m: 50,
        max_altitude_m: 120,
        initial_position: [Math.round(initial_x * 100) / 100, Math.round(initial_y * 100) / 100, Math.round(initial_z * 100) / 100],
        initial_velocity: [
          Math.round((random() * 2 - 1) * params.mean_speed_mps * 0.5 * 100) / 100,
          Math.round((random() * 2 - 1) * params.mean_speed_mps * 0.5 * 100) / 100,
          Math.round((random() * 2 - 1) * 1.0 * 100) / 100
        ],
        position_update_interval_s: 0.1
      },
      auth_trigger: {
        initial_on_connect: false,
        time_offsets_s: [5, 15, 25, 35, 45],
        allow_reauth: true
      },
      link_state: {
        comm_range_m: 500,
        uplink_burst_loss_model: {
          enabled: true,
          p_good_to_bad: lossRate * 0.3,
          p_bad_to_good: 0.3,
          loss_good: 0.01,
          loss_bad: 0.8
        }
      }
    };
  });

  return {
    id: 'uplink_loss_test',
    label: `上行丢包测试 (${(lossRate * 100).toFixed(0)}%)`,
    description: `测试上行链路（UAV→ZSP）丢包率 ${(lossRate * 100).toFixed(0)}% 下的认证协议性能，网络规模 ${size} UAV`,
    duration: 55,
    uavs,
    zsps: [{ id: size, position: [0, 0, 25] }],
    channel: {
      type: 'WiFi',
      datarate: 'ErpOfdmRate6Mbps',
      loss_model: '3gpp_native',
      scenario_type: 'rma',
      carrier_freq_hz: 2.4e9,
      enable_shadowing: true
    },
    security_profile: {
      adversary: 'none',
      attack_model: {
        uplink_loss_rate: lossRate,
        d2z_ack_timeout_s: 2.0,
        max_d2z_attempts: 3,
        desync_template: '',
        desync_experiment_enabled: false,
        desync_multi_round: false,
        desync_boundary_recovery: false,
        desync_attack_every_round: false,
        desync_attack_min_completed_sessions: 0,
        desync_attack_max_completed_sessions: null,
        retry_d2z_after_intercept_s: 2.0,
        downlink_burst_loss_model: {
          enabled: false
        }
      }
    },
    defaultProtocol: 'PMAP_ACK',
    supportsSwarmSize: true,
    supportsLossRate: true,
    stageTag: '丢包测试',
    scenarioNotes: [
      'Gauss-Markov 3D 移动模型',
      `网络规模：${size} UAV`,
      `上行丢包率：${(lossRate * 100).toFixed(0)}%`,
      `机动性档位：${mobilityStress}`,
      '用于测试上行链路丢包对协议的影响'
    ],
    triggerSummary: '时间触发认证 + 自动重认证',
    scenarioProfile: {
      experiment_track: 'link_quality_tests',
      sub_experiment: 'uplink_packet_loss',
      swarm_size: size,
      uplink_loss_rate: lossRate,
      gm3d_stress: mobilityStress
    }
  };
};

const createDownlinkLossTestScenario = (size = 5, lossRate = 0.1, mobilityStress = 'nominal') => {
  const stressParams = {
    hover: { alpha: 0.98, mean_speed_mps: 1.0, speed_std_mps: 0.5 },
    conservative: { alpha: 0.9, mean_speed_mps: 3.0, speed_std_mps: 2.0 },
    nominal: { alpha: 0.8, mean_speed_mps: 5.0, speed_std_mps: 4.0 },
    aggressive: { alpha: 0.6, mean_speed_mps: 10.0, speed_std_mps: 6.0 },
    high_speed: { alpha: 0.4, mean_speed_mps: 15.0, speed_std_mps: 7.0 }
  };

  const params = stressParams[mobilityStress] || stressParams.nominal;

  const uavs = Array.from({ length: size }, (_, idx) => {
    const seed = 20260417 + idx;
    const random = new Math.seedrandom(seed);
    const initial_distance = random() * 80 + 40;
    const initial_angle = random() * Math.PI * 2;
    const initial_x = initial_distance * Math.cos(initial_angle);
    const initial_y = initial_distance * Math.sin(initial_angle);
    const initial_z = 80 + (random() * 40 - 20);

    return {
      id: idx,
      mobility: {
        type: 'gauss_markov_3d',
        seed: seed,
        alpha: params.alpha,
        mean_speed_mps: params.mean_speed_mps,
        speed_std_mps: params.speed_std_mps,
        mean_altitude_m: 80,
        altitude_std_m: 15,
        area_size_x: 300,
        area_size_y: 300,
        min_altitude_m: 50,
        max_altitude_m: 120,
        initial_position: [Math.round(initial_x * 100) / 100, Math.round(initial_y * 100) / 100, Math.round(initial_z * 100) / 100],
        initial_velocity: [
          Math.round((random() * 2 - 1) * params.mean_speed_mps * 0.5 * 100) / 100,
          Math.round((random() * 2 - 1) * params.mean_speed_mps * 0.5 * 100) / 100,
          Math.round((random() * 2 - 1) * 1.0 * 100) / 100
        ],
        position_update_interval_s: 0.1
      },
      auth_trigger: {
        initial_on_connect: false,
        time_offsets_s: [5, 15, 25, 35, 45],
        allow_reauth: true
      },
      link_state: {
        comm_range_m: 500,
        uplink_burst_loss_model: {
          enabled: false
        }
      }
    };
  });

  return {
    id: 'downlink_loss_test',
    label: `下行丢包测试 (${(lossRate * 100).toFixed(0)}%)`,
    description: `测试下行链路（ZSP→UAV）丢包率 ${(lossRate * 100).toFixed(0)}% 下的认证协议性能，网络规模 ${size} UAV`,
    duration: 55,
    uavs,
    zsps: [{ id: size, position: [0, 0, 25] }],
    channel: {
      type: 'WiFi',
      datarate: 'ErpOfdmRate6Mbps',
      loss_model: '3gpp_native',
      scenario_type: 'rma',
      carrier_freq_hz: 2.4e9,
      enable_shadowing: true
    },
    security_profile: {
      adversary: 'none',
      attack_model: {
        downlink_loss_rate: lossRate,
        d2z_ack_timeout_s: 2.0,
        max_d2z_attempts: 3,
        desync_template: '',
        desync_experiment_enabled: false,
        desync_multi_round: false,
        desync_boundary_recovery: false,
        desync_attack_every_round: false,
        desync_attack_min_completed_sessions: 0,
        desync_attack_max_completed_sessions: null,
        retry_d2z_after_intercept_s: 2.0,
        downlink_burst_loss_model: {
          enabled: true,
          p_good_to_bad: lossRate * 0.3,
          p_bad_to_good: 0.3,
          loss_good: 0.01,
          loss_bad: 0.8
        }
      }
    },
    defaultProtocol: 'PMAP_ACK',
    supportsSwarmSize: true,
    supportsLossRate: true,
    stageTag: '丢包测试',
    scenarioNotes: [
      'Gauss-Markov 3D 移动模型',
      `网络规模：${size} UAV`,
      `下行丢包率：${(lossRate * 100).toFixed(0)}%`,
      `机动性档位：${mobilityStress}`,
      '用于测试下行链路丢包对协议的影响'
    ],
    triggerSummary: '时间触发认证 + 自动重认证',
    scenarioProfile: {
      experiment_track: 'link_quality_tests',
      sub_experiment: 'downlink_packet_loss',
      swarm_size: size,
      downlink_loss_rate: lossRate,
      gm3d_stress: mobilityStress
    }
  };
};