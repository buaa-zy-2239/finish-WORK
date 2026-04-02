# Backend/run.py
"""
启动脚本
"""

import sys
import os

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

if __name__ == "__main__":
    import uvicorn
    from Backend.config import config
    
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║  {config.APP_NAME:^58} ║
    ║  Version: {config.APP_VERSION:^48} ║
    ╚══════════════════════════════════════════════════════════════╝
    
    Starting server on http://0.0.0.0:8000
    
    API Endpoints:
      - Health Check: http://localhost:8000/api/v1/health
      - Latest Events: http://localhost:8000/api/v1/events/latest
      - Sessions: http://localhost:8000/api/v1/metrics/sessions
      - Metrics: http://localhost:8000/api/v1/metrics/d2z-summary
      
    WebSocket Endpoints:
      - ws://localhost:8000/ws/d2z-events
      - ws://localhost:8000/ws/d2z-metrics
    """)
    
    uvicorn.run(
        "Backend.app:app",
        host="0.0.0.0",
        port=8000,
        reload=config.DEBUG
    )