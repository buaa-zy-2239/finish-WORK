import React from 'react';

// 协议详细信息
const PROTOCOL_DETAILS = {
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

const ProtocolConfig = ({ protocol, userCount, setUserCount, USER_COUNT_OPTIONS }) => {
  const protocolDetails = PROTOCOL_DETAILS[protocol] || PROTOCOL_DETAILS.PMAP;

  return (
    <div className="protocol-config">
      <div className="protocol-info">
        <h3>{protocolDetails.name}</h3>
        <p className="protocol-description">{protocolDetails.description}</p>
        
        <div className="protocol-flow">
          <h4>协议流程</h4>
          <ol>
            {protocolDetails.flow.map((step, index) => (
              <li key={index}>{step}</li>
            ))}
          </ol>
        </div>
        
        <div className="protocol-features">
          <h4>特性</h4>
          <ul>
            {protocolDetails.features.map((feature, index) => (
              <li key={index}>{feature}</li>
            ))}
          </ul>
        </div>
      </div>
      
      <div className="protocol-specific-configs">
        {protocolDetails.configs.includes('userCount') && (
          <div className="form-group">
            <label>用户数量：</label>
            <select 
              value={userCount} 
              onChange={(e) => setUserCount(parseInt(e.target.value, 10))}
            >
              {USER_COUNT_OPTIONS.map((count) => (
                <option key={count} value={count}>
                  {count} 用户
                </option>
              ))}
            </select>
            <small>三方认证协议中参与的用户数量</small>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProtocolConfig;