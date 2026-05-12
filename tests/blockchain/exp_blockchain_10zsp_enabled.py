"""
区块链功能验证实验4：十地面站区块链同步测试（区块链开启）
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from simulator_builder import SimulationBuilderEnhanced


def main():
    zsp_positions = []
    positions = [
        [-200, -200, 100], [-200, 0, 100], [-200, 200, 100],
        [0, -200, 100], [0, 0, 100], [0, 200, 100],
        [200, -200, 100], [200, 0, 100], [200, 200, 100],
        [0, -400, 100]
    ]
    for i in range(10):
        zsp_positions.append({"id": i + 1, "position": positions[i]})

    waypoints = []
    waypoint_positions = [
        [-180, -180, 80], [-180, 0, 80], [-180, 180, 80],
        [0, -180, 80], [0, 0, 80], [0, 180, 80],
        [180, -180, 80], [180, 0, 80], [180, 180, 80],
        [0, -380, 80],
        [-180, -180, 80]  
    ]
    for i in range(11):
        t = i * 5.0
        waypoints.append((t, waypoint_positions[i]))

    config = {
        "id": "blockchain_test_10zsp_enabled",
        "name": "十地面站测试 - 区块链开启",
        "duration": 90,
        "uavs": [
            {
                "id": 0,
                "mobility": {
                    "type": "waypoint",
                    "waypoints": waypoints,
                    "speed_mps": 15.0
                },
                "auth_trigger": {
                    "initial_on_connect": False,
                    "allow_reauth": False,
                    "on_handover": False,
                    "time_offsets_s": [1, 6, 11, 16, 21, 26, 31, 36, 40, 46, 51]
                },
                "link_state": {
                    "comm_range_m": 1500,
                    "zsp_handover": {
                        "enabled": False,
                        "rssi_threshold_dbm": -95,
                        "hysteresis_db": 5,
                        "min_dwell_time_s": 1.0,
                        "handover_delay_s": 0.3,
                        "reauth_after_handover": False
                    }
                }
            }
        ],
        "zsps": zsp_positions,
        "channel": {
            "type": "CSMA",
            "datarate": "100Mbps"
        },
        "security_profile": {
            "adversary": "none",
            "attack_model": {
                "d2z_ack_timeout_s": 0.1,
                "max_d2z_attempts": 1,
                "d2z_retry_delay_s": 1000.0
            }
        },
        "protocol": "PMAP",
        "enable_blockchain": True
    }

    print(f"\n{'='*70}")
    print("实验4: 十地面站区块链同步测试（区块链开启）")
    print('='*70)
    print(f"协议: {config['protocol']}")
    print(f"区块链: 开启")
    print(f"UAV数量: {len(config['uavs'])}")
    print(f"ZSP数量: {len(config['zsps'])}")
    print(f"仿真时长: {config['duration']}秒")

    try:
        builder = SimulationBuilderEnhanced(config_dict=config)
        result = builder.run()

        print(f"\n实验结果: {result['status']}")
        if 'statistics' in result:
            stats = result['statistics']
            success = stats.get('successful_authentications', 0)
            failed = stats.get('failed_authentications', 0)
            total = success + failed
            print(f"成功认证: {success}")
            print(f"失败认证: {failed}")
            if total > 0:
                print(f"成功率: {success/total*100:.1f}%")

        if 'session_tracker_results' in result:
            st_results = result['session_tracker_results']
            if 'metrics' in st_results:
                metrics = st_results['metrics']
                print(f"\n会话追踪器指标:")
                print(f"  成功率: {metrics.get('authentication', {}).get('success_rate_percent', 'N/A')}%")

        results_dir = _ROOT / "blockchain_experiment_results"
        results_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = results_dir / f"exp4_10zsp_enabled_{timestamp}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n结果已保存到: {filepath}")

    except Exception as e:
        print(f"实验失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()