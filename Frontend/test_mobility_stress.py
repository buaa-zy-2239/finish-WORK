#!/usr/bin/env python3
"""
前端机动应力实验功能测试脚本

测试前端的机动应力实验场景创建、参数设置和仿真执行功能。
"""

import json
import argparse
import requests
import time
from typing import Dict, Any, Optional

class FrontendMobilityStressTester:
    """前端机动应力实验功能测试类"""
    
    def __init__(self, api_base: str = "http://localhost:8000/api/v1"):
        """初始化测试器"""
        self.api_base = api_base
        self.session = requests.Session()
    
    def test_mobility_stress_scenario_creation(self, swarm_size: int, density: int, gm3d_stress: str, protocol: str = "PMAP_ACK") -> Dict[str, Any]:
        """测试机动应力场景创建
        
        Args:
            swarm_size: 网络规模（UAV数量）
            density: 密度（UAV/km²）
            gm3d_stress: GM3D应力档位（conservative/nominal/aggressive）
            protocol: 认证协议（PMAP/PMAP_ACK）
            
        Returns:
            创建的任务信息
        """
        print(f"\n=== 测试机动应力场景创建 ===")
        print(f"网络规模: {swarm_size} UAV")
        print(f"密度: {density} UAV/km²")
        print(f"GM3D应力档位: {gm3d_stress}")
        print(f"协议: {protocol}")
        
        # 构建UAV配置
        uavs = []
        spacing = density * 10  # 密度影响间距
        
        for i in range(swarm_size):
            row = i // 10
            col = i % 10
            x = -200 + col * spacing
            y = -200 + row * spacing
            
            # GM3D参数
            stress_params = {
                'conservative': {"alpha": 0.88, "mean_speed_mps": 3.0, "speed_std_mps": 2.0},
                'nominal': {"alpha": 0.7, "mean_speed_mps": 5.0, "speed_std_mps": 5.0},
                'aggressive': {"alpha": 0.45, "mean_speed_mps": 12.0, "speed_std_mps": 7.0}
            }
            
            params = stress_params.get(gm3d_stress, stress_params['nominal'])
            
            uav = {
                "id": i,
                "mobility": {
                    "type": "gauss_markov_3d",
                    "seed": 20260417 + i,
                    "alpha": params["alpha"],
                    "mean_speed_mps": params["mean_speed_mps"],
                    "speed_std_mps": params["speed_std_mps"],
                    "mean_altitude_m": 80.0,
                    "altitude_std_m": 20.0,
                    "area_size_x": 600.0,
                    "area_size_y": 600.0,
                    "min_altitude_m": 30.0,
                    "max_altitude_m": 200.0,
                    "initial_position": [x, y, 80.0 + (i % 5) * 5],
                    "initial_velocity": [(0.5 - i % 2) * params["mean_speed_mps"], (0.5 - i % 2) * params["mean_speed_mps"], 0.0],
                    "position_update_interval_s": 0.1
                },
                "auth_trigger": {
                    "initial_on_connect": False,
                    "time_offsets_s": [5, 20, 35, 50],
                    "allow_reauth": True
                },
                "link_state": {
                    "comm_range_m": 320
                }
            }
            uavs.append(uav)
        
        # 构建ZSP配置
        zsps = [{
            "id": swarm_size + 1,
            "position": [0, 0, 100]
        }]
        
        # 创建任务
        task_name = f"mobility_stress_test_{swarm_size}_{density}_{gm3d_stress}_{int(time.time())}"
        
        payload = {
            "name": task_name,
            "duration": 60,
            "uavs": uavs,
            "zsps": zsps,
            "protocol": protocol,
            "channel": {"type": "CSMA", "datarate": "100Mbps"},
            "scenario": "mobility_stress_test",
            "scenario_profile": {
                "experiment_track": "main_exp_b",
                "sub_experiment": "mobility_sensitivity",
                "swarm_size": swarm_size,
                "density": density,
                "gm3d_stress": gm3d_stress
            },
            "security_profile": {"adversary": "none"}
        }
        
        try:
            response = self.session.post(f"{self.api_base}/simulation/create", json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if result.get("success"):
                task_id = result.get("task_id")
                print(f"✓ 任务创建成功！任务ID: {task_id}")
                return {"success": True, "task_id": task_id, "task_name": task_name}
            else:
                print(f"✗ 任务创建失败: {result.get('detail', '未知错误')}")
                return {"success": False, "error": result.get('detail', '未知错误')}
                
        except Exception as e:
            print(f"✗ 任务创建异常: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def test_simulation_execution(self, task_id: str) -> Dict[str, Any]:
        """测试仿真执行
        
        Args:
            task_id: 任务ID
            
        Returns:
            执行结果
        """
        print(f"\n=== 测试仿真执行 ===")
        print(f"任务ID: {task_id}")
        
        try:
            # 启动仿真
            response = self.session.post(f"{self.api_base}/simulation/run/{task_id}", timeout=30)
            response.raise_for_status()
            result = response.json()
            
            if result.get("success"):
                print("✓ 仿真启动成功！")
                
                # 等待仿真完成
                print("等待仿真完成...")
                for _ in range(60):  # 最多等待60秒
                    status_response = self.session.get(f"{self.api_base}/simulation/status/{task_id}", timeout=10)
                    status = status_response.json()
                    
                    if status.get("status") == "completed":
                        print("✓ 仿真完成！")
                        return {"success": True, "status": status}
                    elif status.get("status") == "failed":
                        print(f"✗ 仿真失败: {status.get('error', '未知错误')}")
                        return {"success": False, "error": status.get('error', '未知错误')}
                    
                    time.sleep(1)
                
                print("⚠ 仿真超时，可能仍在运行中")
                return {"success": False, "error": "仿真超时"}
            else:
                print(f"✗ 仿真启动失败: {result.get('detail', '未知错误')}")
                return {"success": False, "error": result.get('detail', '未知错误')}
                
        except Exception as e:
            print(f"✗ 仿真执行异常: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def test_results_retrieval(self, task_id: str) -> Dict[str, Any]:
        """测试结果获取
        
        Args:
            task_id: 任务ID
            
        Returns:
            结果数据
        """
        print(f"\n=== 测试结果获取 ===")
        print(f"任务ID: {task_id}")
        
        try:
            # 获取任务配置
            config_response = self.session.get(f"{self.api_base}/simulation/config/{task_id}", timeout=10)
            config_response.raise_for_status()
            config = config_response.json()
            
            # 获取任务状态
            status_response = self.session.get(f"{self.api_base}/simulation/status/{task_id}", timeout=10)
            status_response.raise_for_status()
            status = status_response.json()
            
            # 获取指标
            metrics_response = self.session.get(f"{self.api_base}/simulation/metrics/{task_id}", timeout=10)
            metrics_response.raise_for_status()
            metrics = metrics_response.json()
            
            # 获取事件
            events_response = self.session.get(f"{self.api_base}/simulation/events/{task_id}", timeout=10)
            events_response.raise_for_status()
            events = events_response.json()
            
            print("✓ 结果获取成功！")
            print(f"  - 任务状态: {status.get('status')}")
            print(f"  - 完成时间: {status.get('completed_at', 'N/A')}")
            print(f"  - 事件数量: {len(events.get('events', []))}")
            
            if metrics.get('mechanism'):
                print(f"  - 认证成功率: {metrics['mechanism'].get('recovery_completion_ratio', 'N/A')}")
            
            return {
                "success": True,
                "config": config,
                "status": status,
                "metrics": metrics,
                "events": events
            }
            
        except Exception as e:
            print(f"✗ 结果获取异常: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def run_complete_test(self, swarm_size: int = 10, density: int = 1, gm3d_stress: str = "nominal", protocol: str = "PMAP_ACK") -> Dict[str, Any]:
        """运行完整测试流程
        
        Args:
            swarm_size: 网络规模（UAV数量）
            density: 密度（UAV/km²）
            gm3d_stress: GM3D应力档位（conservative/nominal/aggressive）
            protocol: 认证协议（PMAP/PMAP_ACK）
            
        Returns:
            测试结果
        """
        print(f"\n=======================================")
        print(f"开始完整测试: 机动应力实验")
        print(f"=======================================")
        
        # 1. 创建任务
        create_result = self.test_mobility_stress_scenario_creation(swarm_size, density, gm3d_stress, protocol)
        if not create_result["success"]:
            return {"success": False, "error": "任务创建失败", "details": create_result}
        
        task_id = create_result["task_id"]
        
        # 2. 执行仿真
        execution_result = self.test_simulation_execution(task_id)
        if not execution_result["success"]:
            return {"success": False, "error": "仿真执行失败", "details": execution_result, "task_id": task_id}
        
        # 3. 获取结果
        results_result = self.test_results_retrieval(task_id)
        if not results_result["success"]:
            return {"success": False, "error": "结果获取失败", "details": results_result, "task_id": task_id}
        
        print(f"\n=======================================")
        print(f"测试完成: 全部步骤成功")
        print(f"=======================================")
        
        return {
            "success": True,
            "task_id": task_id,
            "task_name": create_result["task_name"],
            "details": {
                "create": create_result,
                "execution": execution_result,
                "results": results_result
            }
        }

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="前端机动应力实验功能测试")
    parser.add_argument("--api-base", type=str, default="http://localhost:8000", help="API基础URL")
    parser.add_argument("--swarm-size", type=int, default=10, choices=[10, 30, 50, 100], help="网络规模")
    parser.add_argument("--density", type=int, default=1, choices=[1, 10, 50], help="密度")
    parser.add_argument("--gm3d-stress", type=str, default="nominal", choices=["conservative", "nominal", "aggressive"], help="GM3D应力档位")
    parser.add_argument("--protocol", type=str, default="PMAP_ACK", choices=["PMAP", "PMAP_ACK"], help="认证协议")
    parser.add_argument("--all", action="store_true", help="测试所有参数组合")
    
    args = parser.parse_args()
    
    tester = FrontendMobilityStressTester(api_base=args.api_base)
    
    if args.all:
        # 测试所有参数组合
        swarm_sizes = [10, 30]
        densities = [1, 10]
        gm3d_stresses = ["conservative", "nominal", "aggressive"]
        protocols = ["PMAP", "PMAP_ACK"]
        
        results = []
        
        for swarm_size in swarm_sizes:
            for density in densities:
                for gm3d_stress in gm3d_stresses:
                    for protocol in protocols:
                        result = tester.run_complete_test(swarm_size, density, gm3d_stress, protocol)
                        results.append({
                            "params": {
                                "swarm_size": swarm_size,
                                "density": density,
                                "gm3d_stress": gm3d_stress,
                                "protocol": protocol
                            },
                            "result": result
                        })
        
        # 输出测试结果
        print(f"\n=======================================")
        print(f"所有测试结果汇总")
        print(f"=======================================")
        
        for i, test_result in enumerate(results):
            params = test_result["params"]
            result = test_result["result"]
            
            status = "✓" if result["success"] else "✗"
            print(f"{status} 测试 {i+1}: {params['swarm_size']}UAV, {params['density']}density, {params['gm3d_stress']}, {params['protocol']}")
            if not result["success"]:
                print(f"  错误: {result['error']}")
        
        # 保存结果到文件
        with open("mobility_stress_test_results.json", "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n测试结果已保存到: mobility_stress_test_results.json")
        
    else:
        # 测试单个参数组合
        result = tester.run_complete_test(
            swarm_size=args.swarm_size,
            density=args.density,
            gm3d_stress=args.gm3d_stress,
            protocol=args.protocol
        )
        
        # 保存结果到文件
        with open("mobility_stress_test_result.json", "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        print(f"\n测试结果已保存到: mobility_stress_test_result.json")

if __name__ == "__main__":
    main()