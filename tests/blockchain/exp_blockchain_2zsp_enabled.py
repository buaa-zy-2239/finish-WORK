"""
区块链功能验证实验2：双地面站跨区域认证测试（区块链开启）
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
    config = {
        "id": "blockchain_test_2zsp_enabled",
        "name": "双地面站测试 - 区块链开启",
        "duration": 100,
        "uavs": [
            {
                "id": 0,
                "mobility": {
                    "type": "transit",
                    "start": [-500.0, 0.0, 100.0],
                    "end": [500.0, 0.0, 100.0],
                    "speed_mps": 8.0
                },
                "auth_trigger": {
                    "initial_on_connect": True,
                    "allow_reauth": True,
                    "on_handover": True,
                    "handover_delay_s": 0.5
                },
                "link_state": {
                    "comm_range_m": 500,
                    "zsp_handover": {
                        "enabled": True,
                        "rssi_threshold_dbm": -95,
                        "hysteresis_db": 5,
                        "min_dwell_time_s": 2.0,
                        "handover_delay_s": 0.5,
                        "reauth_after_handover": True
                    }
                }
            }
        ],
        "zsps": [
            {"id": 1, "position": [-200.0, 0.0, 100.0]},
            {"id": 2, "position": [200.0, 0.0, 100.0]}
        ],
        "channel": {
            "type": "CSMA",
            "datarate": "100Mbps"
        },
        "security_profile": {
            "adversary": "none",
            "attack_model": {
                "d2z_ack_timeout_s": 5.0,
                "max_d2z_attempts": 1,
                "d2z_retry_delay_s": 1.0
            }
        },
        "protocol": "PMAP",
        "enable_blockchain": True
    }

    print(f"\n{'='*70}")
    print("实验2: 双地面站跨区域认证测试（区块链开启）")
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
        filepath = results_dir / f"exp2_2zsp_enabled_{timestamp}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n结果已保存到: {filepath}")

    except Exception as e:
        print(f"实验失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()