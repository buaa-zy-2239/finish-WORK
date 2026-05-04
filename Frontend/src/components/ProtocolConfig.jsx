import React from 'react';
import { PROTOCOL_DETAILS } from '../constants';

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