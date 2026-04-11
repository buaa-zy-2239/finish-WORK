// Frontend/src/App.jsx
import React, { useState } from 'react';
import SimulationManager from './components/SimulationManager';
import AnalysisDashboard from './components/AnalysisDashboard';
import './App.css';

function App() {
  const [currentTab, setCurrentTab] = useState('simulation');

  return (
    <div className="App">
      <header className="app-header">
        <h1>🚁 UAV D2Z 安全认证协议仿真平台</h1>
        <p>一站式无人机网络安全认证协议仿真和分析工具</p>
      </header>

      <nav className="app-nav">
        <button
          className={`nav-btn ${currentTab === 'simulation' ? 'active' : ''}`}
          onClick={() => setCurrentTab('simulation')}
        >
          📋 仿真管理
        </button>
        <button
          className={`nav-btn ${currentTab === 'analysis' ? 'active' : ''}`}
          onClick={() => setCurrentTab('analysis')}
        >
          📊 结果分析
        </button>
      </nav>

      <main className="app-main">
        {currentTab === 'simulation' && <SimulationManager />}
        {currentTab === 'analysis' && <AnalysisDashboard />}
      </main>

      <footer className="app-footer">
        <p>&copy; 2026 UAV D2Z Authentication Protocol Simulation Platform</p>
      </footer>
    </div>
  );
}

export default App;