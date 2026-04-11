import pytest
import requests
import json
from Backend.services.api_server import D2ZApiServer
import threading
import time

@pytest.fixture
def api_server():
    """启动API服务器fixture"""
    server = D2ZApiServer()
    thread = threading.Thread(target=lambda: server.run(port=5555), daemon=True)
    thread.start()
    time.sleep(2)  # 等待服务器启动
    yield server
    # 清理

class TestD2ZAPI:
    BASE_URL = "http://127.0.0.1:5555/api"
    
    def test_health(self, api_server):
        """测试健康检查"""
        resp = requests.get(f"{self.BASE_URL}/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"
    
    def test_get_metrics(self, api_server):
        """测试获取指标"""
        resp = requests.get(f"{self.BASE_URL}/metrics/summary")
        assert resp.status_code == 200
        assert "authentication" in resp.json()
    
    def test_get_sessions(self, api_server):
        """测试获取会话"""
        resp = requests.get(f"{self.BASE_URL}/sessions")
        assert resp.status_code == 200
        assert "sessions" in resp.json()
    
    def test_get_specific_session(self, api_server):
        """测试获取特定会话"""
        resp = requests.get(f"{self.BASE_URL}/sessions/0/2")
        assert resp.status_code in [200, 404]
    
    def test_pagination(self, api_server):
        """测试事件分页"""
        resp = requests.get(f"{self.BASE_URL}/events?page=1&limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert "page" in data
        assert "limit" in data
        assert data["limit"] <= 5