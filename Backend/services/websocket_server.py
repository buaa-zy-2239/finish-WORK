from flask import Flask
from flask_socketio import SocketIO, emit, join_room
from Backend.services.log_service import LogService
import threading
import time

class D2ZWebSocketServer:
    def __init__(self, app, log_dir="logs"):
        self.app = app
        self.socketio = SocketIO(app, cors_allowed_origins="*")
        self.log_service = LogService(log_dir)
        self.monitoring = False
        self._setup_handlers()
    
    def _setup_handlers(self):
        """设置WebSocket事件处理器"""
        
        @self.socketio.on('connect')
        def handle_connect():
            print(f'Client connected: {request.sid}')
            emit('response', {'data': 'Connected to D2Z Server'})
        
        @self.socketio.on('start_monitoring')
        def start_monitoring():
            """开始实时监控"""
            join_room('monitoring')
            self.monitoring = True
            
            # 启动后台线程进行监控
            def monitor():
                last_count = 0
                while self.monitoring:
                    current_status = self.log_service.get_log_status()
                    
                    if current_status['event_count'] > last_count:
                        # 有新事件，广播更新
                        self.socketio.emit('new_event', {
                            'status': current_status,
                            'timestamp': time.time()
                        }, room='monitoring')
                        last_count = current_status['event_count']
                    
                    time.sleep(1)
            
            thread = threading.Thread(target=monitor, daemon=True)
            thread.start()
            
            emit('monitoring_started', {'timestamp': time.time()})
        
        @self.socketio.on('stop_monitoring')
        def stop_monitoring():
            """停止监控"""
            self.monitoring = False
            emit('monitoring_stopped', {'timestamp': time.time()})
        
        @self.socketio.on('request_metrics')
        def request_metrics():
            """请求最新指标"""
            metrics = self.log_service.get_metrics()
            emit('metrics_update', metrics)
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            print(f'Client disconnected: {request.sid}')
            self.monitoring = False
    
    def run(self, host='0.0.0.0', port=5001):
        """启动WebSocket服务器"""
        print(f"🔌 Starting WebSocket Server on {host}:{port}")
        self.socketio.run(self.app, host=host, port=port)