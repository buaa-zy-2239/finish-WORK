# Backend/services/api_server.py
"""
D2Z认证协议 REST API 服务器
完整的HTTP API接口，支持日志查询、会话分析、指标导出
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from Backend.core.log_parser import D2ZLogParser
from Backend.core.event_models import D2ZEvent, D2ZPhase
from Backend.analysis.protocol_analyzer import D2ZAnalyzer
from Backend.services.log_service import LogService
import time
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class D2ZApiServer:
    """D2Z认证协议 REST API 服务器"""
    
    def __init__(self, log_dir: str = "logs"):
        """
        初始化API服务器
        
        Args:
            log_dir: 日志目录路径
        """
        self.app = Flask(__name__)
        CORS(self.app)
        self.log_dir = Path(log_dir)
        self.log_service = LogService(log_dir)
        
        # 错误处理
        self._setup_error_handlers()
        
        # 设置��由
        self._setup_routes()
    
    def _setup_error_handlers(self):
        """配置全局错误处理"""
        
        @self.app.errorhandler(400)
        def bad_request(error):
            return jsonify({
                "error": "Bad Request",
                "message": str(error),
                "timestamp": time.time()
            }), 400
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({
                "error": "Not Found",
                "message": str(error),
                "timestamp": time.time()
            }), 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            logger.error(f"Internal server error: {error}")
            return jsonify({
                "error": "Internal Server Error",
                "message": str(error),
                "timestamp": time.time()
            }), 500
    
    def _setup_routes(self):
        """设置所有API路由"""
        
        # ==================== 健康检查 ====================
        @self.app.route('/api/health', methods=['GET'])
        def health():
            """健康检查端点"""
            return jsonify({
                "status": "healthy",
                "service": "D2Z-Backend-API",
                "version": "1.0.0",
                "timestamp": time.time()
            }), 200
        
        # ==================== 日志管理 ====================
        @self.app.route('/api/logs/reload', methods=['POST'])
        def reload_logs():
            """重新加载日志文件"""
            try:
                self.log_service.load_logs()
                return jsonify({
                    "status": "success",
                    "message": "Logs reloaded successfully",
                    "timestamp": time.time()
                }), 200
            except Exception as e:
                logger.error(f"Failed to reload logs: {e}")
                return jsonify({
                    "error": str(e),
                    "timestamp": time.time()
                }), 500
        
        @self.app.route('/api/logs/status', methods=['GET'])
        def get_log_status():
            """获取日志状态"""
            try:
                status = self.log_service.get_log_status()
                return jsonify(status), 200
            except Exception as e:
                logger.error(f"Failed to get log status: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/logs/list', methods=['GET'])
        def list_logs():
            """列出所有日志文件"""
            try:
                log_files = list(self.log_dir.glob("*.jsonl"))
                files_info = []
                
                for f in sorted(log_files, key=lambda x: x.stat().st_ctime, reverse=True):
                    files_info.append({
                        "name": f.name,
                        "size_bytes": f.stat().st_size,
                        "created_at": f.stat().st_ctime,
                        "modified_at": f.stat().st_mtime
                    })
                
                return jsonify({
                    "total": len(files_info),
                    "files": files_info
                }), 200
            except Exception as e:
                logger.error(f"Failed to list logs: {e}")
                return jsonify({"error": str(e)}), 500
        
        # ==================== 事件查询 ====================
        @self.app.route('/api/events', methods=['GET'])
        def get_events():
            """
            获取所有事件（支持分页和过滤）
            
            查询参数:
                - page: 页码 (默认1)
                - limit: 每页数量 (默认20, 最大100)
                - uav_id: 过滤UAV ID
                - zsp_id: 过滤ZSP ID
                - phase: 过滤事件阶段
            """
            try:
                page = request.args.get('page', 1, type=int)
                limit = min(request.args.get('limit', 20, type=int), 100)
                uav_id = request.args.get('uav_id', type=int)
                zsp_id = request.args.get('zsp_id', type=int)
                phase = request.args.get('phase', type=str)
                
                # 获取所有事件（已转换为字典）
                all_events = self.log_service.get_events()
                
                # 过滤条件
                filtered_events = all_events
                
                if uav_id is not None:
                    filtered_events = [e for e in filtered_events if e.get('uav_id') == uav_id]
                
                if zsp_id is not None:
                    filtered_events = [e for e in filtered_events if e.get('zsp_id') == zsp_id]
                
                if phase is not None:
                    filtered_events = [e for e in filtered_events if e.get('phase') == phase]
                
                # 分页
                start = (page - 1) * limit
                end = start + limit
                paginated_events = filtered_events[start:end]
                
                return jsonify({
                    "pagination": {
                        "page": page,
                        "limit": limit,
                        "total": len(filtered_events),
                        "has_next": end < len(filtered_events)
                    },
                    "events": paginated_events
                }), 200
            
            except Exception as e:
                logger.error(f"Failed to get events: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/events/count', methods=['GET'])
        def count_events():
            """获取事件总数"""
            try:
                events = self.log_service.get_events()
                return jsonify({"total": len(events)}), 200
            except Exception as e:
                logger.error(f"Failed to count events: {e}")
                return jsonify({"error": str(e)}), 500
        
        # ==================== 会话查询 ====================
        @self.app.route('/api/sessions', methods=['GET'])
        def get_sessions():
            """获取所有会话"""
            try:
                analyzer = self.log_service.analyzer
                if analyzer is None:
                    return jsonify({
                        "total": 0,
                        "sessions": []
                    }), 200
                
                sessions = analyzer.get_all_sessions()
                return jsonify({
                    "total": len(sessions),
                    "sessions": sessions
                }), 200
            
            except Exception as e:
                logger.error(f"Failed to get sessions: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/sessions/<int:uav_id>/<int:zsp_id>', 
                        methods=['GET'])
        def get_session(uav_id, zsp_id):
            """获取特定会话详情"""
            try:
                analyzer = self.log_service.analyzer
                if analyzer is None:
                    return jsonify({"error": "No analyzer available"}), 503
                
                session = analyzer.get_session(uav_id, zsp_id)
                if session is None:
                    return jsonify({
                        "error": "Session not found",
                        "uav_id": uav_id,
                        "zsp_id": zsp_id
                    }), 404
                
                return jsonify(session), 200
            
            except Exception as e:
                logger.error(f"Failed to get session {uav_id}/{zsp_id}: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/sessions/<int:uav_id>/<int:zsp_id>/timeline', 
                        methods=['GET'])
        def get_session_timeline(uav_id, zsp_id):
            """获取特定会话的事件时间线"""
            try:
                analyzer = self.log_service.analyzer
                if analyzer is None:
                    return jsonify({"error": "No analyzer available"}), 503
                
                timeline = analyzer.get_session_timeline(uav_id, zsp_id)
                return jsonify({
                    "uav_id": uav_id,
                    "zsp_id": zsp_id,
                    "events": timeline,
                    "count": len(timeline)
                }), 200
            
            except Exception as e:
                logger.error(f"Failed to get timeline {uav_id}/{zsp_id}: {e}")
                return jsonify({"error": str(e)}), 500
        
        # ==================== UAV统计 ====================
        @self.app.route('/api/uavs/<int:uav_id>/statistics', 
                        methods=['GET'])
        def get_uav_statistics(uav_id):
            """获取特定UAV的统计信息"""
            try:
                analyzer = self.log_service.analyzer
                if analyzer is None:
                    return jsonify({"error": "No analyzer available"}), 503
                
                stats = analyzer.get_uav_statistics(uav_id)
                return jsonify(stats), 200
            
            except Exception as e:
                logger.error(f"Failed to get UAV stats: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/uavs', methods=['GET'])
        def list_uavs():
            """列出所有UAV统计"""
            try:
                analyzer = self.log_service.analyzer
                if analyzer is None:
                    return jsonify({"uavs": []}), 200
                
                # 从会话中提取UAV ID
                sessions = analyzer.get_all_sessions()
                uav_ids = set(s['uav_id'] for s in sessions)
                
                uav_stats = []
                for uav_id in sorted(uav_ids):
                    stats = analyzer.get_uav_statistics(uav_id)
                    uav_stats.append(stats)
                
                return jsonify({
                    "total_uavs": len(uav_stats),
                    "uavs": uav_stats
                }), 200
            
            except Exception as e:
                logger.error(f"Failed to list UAVs: {e}")
                return jsonify({"error": str(e)}), 500
        
        # ==================== 指标查询 ====================
        @self.app.route('/api/metrics/summary', methods=['GET'])
        def get_metrics_summary():
            """获取整体指标摘要"""
            try:
                metrics = self.log_service.get_metrics()
                return jsonify(metrics), 200
            
            except Exception as e:
                logger.error(f"Failed to get metrics: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/metrics/authentication', methods=['GET'])
        def get_auth_metrics():
            """获取认证相关指标"""
            try:
                metrics = self.log_service.get_metrics()
                return jsonify(metrics.get("authentication", {})), 200
            
            except Exception as e:
                logger.error(f"Failed to get auth metrics: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/metrics/messaging', methods=['GET'])
        def get_messaging_metrics():
            """获取消息相关指标"""
            try:
                metrics = self.log_service.get_metrics()
                return jsonify(metrics.get("messaging", {})), 200
            
            except Exception as e:
                logger.error(f"Failed to get messaging metrics: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/metrics/timing', methods=['GET'])
        def get_timing_metrics():
            """获取时间相关指标"""
            try:
                metrics = self.log_service.get_metrics()
                return jsonify(metrics.get("timing", {})), 200
            
            except Exception as e:
                logger.error(f"Failed to get timing metrics: {e}")
                return jsonify({"error": str(e)}), 500
        
        # ==================== 分析端点 ====================
        @self.app.route('/api/analysis/success-rate', methods=['GET'])
        def get_success_rate():
            """获取认证成功率分析"""
            try:
                metrics = self.log_service.get_metrics()
                auth = metrics.get("authentication", {})
                return jsonify({
                    "success_rate_percent": auth.get("success_rate_percent", 0),
                    "total_sessions": auth.get("total_sessions", 0),
                    "successful_sessions": auth.get("successful", 0),
                    "failed_sessions": auth.get("failed", 0)
                }), 200
            
            except Exception as e:
                logger.error(f"Failed to get success rate: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/analysis/performance', methods=['GET'])
        def get_performance():
            """获取性能分析"""
            try:
                metrics = self.log_service.get_metrics()
                return jsonify({
                    "timing": metrics.get("timing", {}),
                    "messaging": metrics.get("messaging", {})
                }), 200
            
            except Exception as e:
                logger.error(f"Failed to get performance: {e}")
                return jsonify({"error": str(e)}), 500
        
        # ==================== 导出端点 ====================
        @self.app.route('/api/export/metrics', methods=['GET'])
        def export_metrics():
            """导出所有指标为JSON"""
            try:
                metrics = self.log_service.get_metrics()
                return jsonify(metrics), 200
            
            except Exception as e:
                logger.error(f"Failed to export metrics: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/export/sessions', methods=['GET'])
        def export_sessions():
            """导出所有会话为JSON"""
            try:
                analyzer = self.log_service.analyzer
                if analyzer is None:
                    return jsonify({"sessions": []}), 200
                
                sessions = analyzer.get_all_sessions()
                return jsonify({
                    "export_time": datetime.now().isoformat(),
                    "total_sessions": len(sessions),
                    "sessions": sessions
                }), 200
            
            except Exception as e:
                logger.error(f"Failed to export sessions: {e}")
                return jsonify({"error": str(e)}), 500
        
        @self.app.route('/api/export/events', methods=['GET'])
        def export_events():
            """导出所有事件为JSON"""
            try:
                events = self.log_service.get_events()
                return jsonify({
                    "export_time": datetime.now().isoformat(),
                    "total_events": len(events),
                    "events": events
                }), 200
            
            except Exception as e:
                logger.error(f"Failed to export events: {e}")
                return jsonify({"error": str(e)}), 500
    
    def run(self, host='127.0.0.1', port=5000, debug=False):
        """
        启动API服务器
        
        Args:
            host: 绑定地址
            port: 监听端口
            debug: 调试模式
        """
        print(f"🚀 Starting D2Z API Server on {host}:{port}")
        print(f"📊 API documentation available at http://{host}:{port}/api/health")
        self.app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == '__main__':
    import sys
    
    # 命令行参数
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    log_dir = sys.argv[2] if len(sys.argv) > 2 else "logs"
    
    # 启动服务器
    server = D2ZApiServer(log_dir=log_dir)
    server.run(host='0.0.0.0', port=port, debug=False)