# test_d2z_backend_integration.py
"""
D2Z认证流程与后端接口完整集成测试
- 包含所有必要的import
- 处理路径配置
- 完整的执行链验证
"""

import sys
import os
import json
import time
import glob
from pathlib import Path
from typing import Optional, List, Dict, Any

# ============================================================
# 【第一阶段】路径配置 - 必须在所有导入前执行
# ============================================================

# 获取项目根目录
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

# 确保后端模块可以找到
BACKEND_ROOT = PROJECT_ROOT / "Backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

print(f"[SETUP] Project root: {PROJECT_ROOT}")
print(f"[SETUP] Backend path: {BACKEND_ROOT}")
print(f"[SETUP] Python path: {sys.path[:3]}")


# ============================================================
# 【第二阶段】前端仿真框架导入
# ============================================================

try:
    from Simulator.simulator_builder import SimulationBuilder
    print("[IMPORT] ✓ Simulator.simulator_builder")
except ImportError as e:
    print(f"[ERROR] Failed to import Simulator: {e}")
    sys.exit(1)

try:
    from Common.logging_framework import (
        LogManager, UAVLogger, ZSPLogger,
        AuthenticationPhase, get_log_manager
    )
    print("[IMPORT] ✓ Common.logging_framework")
except ImportError as e:
    print(f"[ERROR] Failed to import logging framework: {e}")
    sys.exit(1)

try:
    from Entity.UAV.BaseUAV import BaseUAV
    from Entity.ZSP.BaseZSP import BaseZSP
    print("[IMPORT] ✓ Entity (BaseUAV, BaseZSP)")
except ImportError as e:
    print(f"[ERROR] Failed to import Entity: {e}")
    sys.exit(1)


# ============================================================
# 【第三阶段】后端框架导入
# ============================================================

try:
    from Backend.config import config
    print("[IMPORT] ✓ Backend.config")
except ImportError as e:
    print(f"[ERROR] Failed to import Backend.config: {e}")
    sys.exit(1)

try:
    from Backend.core.log_parser import D2ZLogParser
    from Backend.core.event_models import D2ZEvent, D2ZPhase
    print("[IMPORT] ✓ Backend.core (log_parser, event_models)")
except ImportError as e:
    print(f"[ERROR] Failed to import Backend.core: {e}")
    sys.exit(1)

try:
    from Backend.analysis.protocol_analyzer import D2ZAnalyzer
    print("[IMPORT] ✓ Backend.analysis.protocol_analyzer")
except ImportError as e:
    print(f"[ERROR] Failed to import Backend.analysis: {e}")
    sys.exit(1)

try:
    from Backend.services.log_service import log_service
    print("[IMPORT] ✓ Backend.services.log_service")
except ImportError as e:
    print(f"[ERROR] Failed to import Backend.services: {e}")
    sys.exit(1)


# ============================================================
# 【第四阶段】测试用例定义
# ============================================================

class D2ZIntegrationTest:
    """D2Z认证流程与后端接口集成测试"""
    
    def __init__(self):
        """初始化测试环境"""
        self.project_root = PROJECT_ROOT
        self.log_dir = config.get_log_dir()
        self.config_path = PROJECT_ROOT / "config.json"
        self.simulation_result = None
        self.parsed_events = []
        self.sessions = []
        self.metrics = {}
        
        print(f"\n[TEST SETUP]")
        print(f"  Project root: {self.project_root}")
        print(f"  Log directory: {self.log_dir}")
        print(f"  Config file: {self.config_path}")
    
    # ================================================
    # 【第五阶段】第1步：验证配置
    # ================================================
    
    def step_1_verify_config(self) -> bool:
        """
        验证配置文件
        
        Returns:
            bool: 配置是否有效
        """
        print("\n[STEP 1] Verifying configuration...")
        
        try:
            if not self.config_path.exists():
                print(f"  ❌ Config file not found: {self.config_path}")
                return False
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            
            print(f"  ✓ Config file found: {self.config_path}")
            print(f"  ✓ Log directory: {self.log_dir}")
            print(f"  ✓ Config keys: {list(cfg.keys())}")
            
            return True
        
        except Exception as e:
            print(f"  ❌ Config verification failed: {e}")
            return False
    
    # ================================================
    # 【第六阶段】第2步：启动仿真
    # ================================================
    
    def step_2_run_simulation(self) -> bool:
        """
        运行D2Z认证仿真
        
        Returns:
            bool: 仿真是否成功
        """
        print("\n[STEP 2] Running D2Z authentication simulation...")
        
        try:
            builder = SimulationBuilder(config_path=str(self.config_path))
            
            print("  → Starting simulator_builder.run()...")
            self.simulation_result = builder.run()
            
            print("  ✓ Simulation completed")
            print(f"  ✓ Result type: {type(self.simulation_result)}")
            
            return True
        
        except Exception as e:
            print(f"  ❌ Simulation failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ================================================
    # 【第七阶段】第3步：验证日志文件生成
    # ================================================
    
    def step_3_verify_log_files(self) -> bool:
        """
        验证日志文件是否正确生成
        
        Returns:
            bool: 日志文件是否存在
        """
        print("\n[STEP 3] Verifying log files...")
        
        try:
            # 等待日志文件写入
            time.sleep(1)
            
            # 查找UAV日志
            uav_logs = glob.glob(os.path.join(self.log_dir, "sim_*_uav_*.jsonl"))
            zsp_logs = glob.glob(os.path.join(self.log_dir, "sim_*_zsp_*.jsonl"))
            
            print(f"  → Log directory: {self.log_dir}")
            print(f"  → UAV logs: {len(uav_logs)}")
            print(f"  → ZSP logs: {len(zsp_logs)}")
            
            # 列出所有日志文件
            all_logs = glob.glob(os.path.join(self.log_dir, "sim_*.jsonl"))
            for log_file in all_logs:
                file_size = os.path.getsize(log_file)
                print(f"    ✓ {os.path.basename(log_file)} ({file_size} bytes)")
            
            if not uav_logs and not zsp_logs:
                print(f"  ❌ No log files found in {self.log_dir}")
                return False
            
            if not uav_logs:
                print(f"  ⚠️  No UAV logs found")
                return False
            
            if not zsp_logs:
                print(f"  ⚠️  No ZSP logs found")
                return False
            
            print("  ✓ Log files verified")
            return True
        
        except Exception as e:
            print(f"  ❌ Log file verification failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ================================================
    # 【第八阶段】第4步：后端日志解析
    # ================================================
    
    def step_4_parse_logs(self) -> bool:
        """
        后端解析日志文件
        
        Returns:
            bool: 日志是否被成功解析
        """
        print("\n[STEP 4] Backend log parsing...")
        
        try:
            print(f"  → Parsing logs from: {self.log_dir}")
            
            # 调用后端日志解析
            self.parsed_events = D2ZLogParser.parse_all_logs(self.log_dir)
            
            print(f"  ✓ Total events parsed: {len(self.parsed_events)}")
            
            if len(self.parsed_events) == 0:
                print(f"  ❌ No events were parsed!")
                return False
            
            # 统计事件类型
            event_types = {}
            phases = {}
            
            for event in self.parsed_events:
                # 统计事件类型
                phase_str = event.phase.value if hasattr(event.phase, 'value') else str(event.phase)
                phases[phase_str] = phases.get(phase_str, 0) + 1
                
                msg_type = event.message_type or "N/A"
                event_types[msg_type] = event_types.get(msg_type, 0) + 1
            
            print(f"\n  Event breakdown:")
            for phase, count in sorted(phases.items()):
                print(f"    - {phase}: {count}")
            
            print(f"\n  Message types:")
            for msg_type, count in sorted(event_types.items()):
                print(f"    - {msg_type}: {count}")
            
            print("  ✓ Log parsing completed")
            return True
        
        except Exception as e:
            print(f"  ❌ Log parsing failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ================================================
    # 【第九阶段】第5步：会话识别与分析
    # ================================================
    
    def step_5_analyze_sessions(self) -> bool:
        """
        分析D2Z认证会话
        
        Returns:
            bool: 会话是否被正确识别
        """
        print("\n[STEP 5] D2Z session analysis...")
        
        try:
            if not self.parsed_events:
                print("  ❌ No events to analyze")
                return False
            
            # 创建分析器
            analyzer = D2ZAnalyzer(self.parsed_events)
            
            # 获取会话信息
            self.sessions = analyzer.get_all_sessions()
            
            print(f"  ✓ Total sessions identified: {len(self.sessions)}")
            
            if not self.sessions:
                print("  ⚠️  No sessions were identified")
                # 这可能不是失败，取决于仿真配置
                return True
            
            # 详细打印每个会话
            for i, session in enumerate(self.sessions, 1):
                print(f"\n  Session {i}:")
                print(f"    UAV ID: {session.get('uav_id', 'N/A')}")
                print(f"    ZSP ID: {session.get('zsp_id', 'N/A')}")
                print(f"    Status: {'✓ Success' if session.get('success') else '✗ Failed'}")
                print(f"    Duration: {session.get('duration_seconds', 0):.4f}s")
                print(f"    Events: {session.get('total_events', 0)}")
                print(f"    Messages: {session.get('message_count', 0)}")
            
            print("\n  ✓ Session analysis completed")
            return True
        
        except Exception as e:
            print(f"  ❌ Session analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ================================================
    # 【第十阶段】第6步：指标计算
    # ================================================
    
    def step_6_calculate_metrics(self) -> bool:
        """
        计算D2Z协议效率指标
        
        Returns:
            bool: 指标是否被正确计算
        """
        print("\n[STEP 6] Metrics calculation...")
        
        try:
            if not self.parsed_events:
                print("  ❌ No events for metrics calculation")
                return False
            
            # 创建分析器
            analyzer = D2ZAnalyzer(self.parsed_events)
            
            # 获取指标
            self.metrics = analyzer.get_summary()
            
            print(f"  ✓ Metrics calculated")
            
            # 打印认证指标
            auth_metrics = self.metrics.get("authentication", {})
            print(f"\n  Authentication metrics:")
            print(f"    Total sessions: {auth_metrics.get('total_sessions', 0)}")
            print(f"    Successful: {auth_metrics.get('successful', 0)}")
            print(f"    Failed: {auth_metrics.get('failed', 0)}")
            print(f"    Success rate: {auth_metrics.get('success_rate_percent', 0):.2f}%")
            
            # 打印消息指标
            msg_metrics = self.metrics.get("messaging", {})
            print(f"\n  Messaging metrics:")
            print(f"    Total messages: {msg_metrics.get('total_messages', 0)}")
            print(f"    Avg size: {msg_metrics.get('avg_size_bytes', 0):.2f} bytes")
            print(f"    Total bytes: {msg_metrics.get('total_bytes', 0)}")
            
            # 打印时间指标
            timing_metrics = self.metrics.get("timing", {})
            print(f"\n  Timing metrics:")
            print(f"    Avg duration: {timing_metrics.get('avg_duration_seconds', 0):.4f}s")
            print(f"    Min duration: {timing_metrics.get('min_duration_seconds', 0):.4f}s")
            print(f"    Max duration: {timing_metrics.get('max_duration_seconds', 0):.4f}s")
            
            # 打印错误指标
            error_metrics = self.metrics.get("errors", {})
            print(f"\n  Error metrics:")
            print(f"    Total errors: {error_metrics.get('total', 0)}")
            print(f"    M1 errors: {error_metrics.get('M1_errors', 0)}")
            print(f"    M2 errors: {error_metrics.get('M2_errors', 0)}")
            
            print("\n  ✓ Metrics calculation completed")
            return True
        
        except Exception as e:
            print(f"  ❌ Metrics calculation failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ================================================
    # 【第十一阶段】第7步：后端API服务验证
    # ================================================
    
    def step_7_verify_api_service(self) -> bool:
        """
        验证后端可以通过LogService提供API
        
        Returns:
            bool: API服务是否可用
        """
        print("\n[STEP 7] Backend API service verification...")
        
        try:
            # 测试LogService（单例）
            print("  → Testing log_service singleton...")
            
            log_service.load_logs(force_reload=True)
            print("  ✓ log_service.load_logs() called")
            
            # 获取事件
            latest_events = log_service.get_events(limit=10)
            print(f"  ✓ log_service.get_events() returned {len(latest_events)} events")
            
            # 获取指标
            metrics = log_service.get_metrics()
            print(f"  ✓ log_service.get_metrics() returned metrics")
            
            # 获取会话
            sessions = log_service.get_sessions()
            print(f"  ✓ log_service.get_sessions() returned {len(sessions)} sessions")
            
            # 获取状态
            status = log_service.get_log_status()
            print(f"  ✓ log_service.get_log_status() returned status")
            print(f"    - Total events: {status.get('total_events', 0)}")
            print(f"    - Sessions: {status.get('sessions', 0)}")
            
            print("\n  ✓ API service verification completed")
            return True
        
        except Exception as e:
            print(f"  ❌ API service verification failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ================================================
    # 【第十二阶段】执行完整测试
    # ================================================
    
    def run_all_steps(self) -> bool:
        """
        执行所有测试步骤
        
        Returns:
            bool: 所有步骤是否都通过
        """
        print("=" * 70)
        print("D2Z Authentication Backend Integration Test Suite")
        print("=" * 70)
        
        results = {
            "step_1_verify_config": self.step_1_verify_config(),
            "step_2_run_simulation": self.step_2_run_simulation(),
            "step_3_verify_log_files": self.step_3_verify_log_files(),
            "step_4_parse_logs": self.step_4_parse_logs(),
            "step_5_analyze_sessions": self.step_5_analyze_sessions(),
            "step_6_calculate_metrics": self.step_6_calculate_metrics(),
            "step_7_verify_api_service": self.step_7_verify_api_service(),
        }
        
        # 打印总结
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        
        passed = sum(1 for v in results.values() if v)
        total = len(results)
        
        for step, result in results.items():
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"  {status}: {step}")
        
        print(f"\nTotal: {passed}/{total} steps passed")
        print("=" * 70)
        
        return all(results.values())


# ============================================================
# 【第十三阶段】主函数入口
# ============================================================

def main():
    """主函数"""
    
    print("\n" + "=" * 70)
    print("D2Z Backend Integration Test - Initialization")
    print("=" * 70)
    
    try:
        # 创建测试实例
        test = D2ZIntegrationTest()
        
        # 运行所有测试步骤
        success = test.run_all_steps()
        
        # 返回状态码
        sys.exit(0 if success else 1)
    
    except Exception as e:
        print(f"\n[FATAL ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()