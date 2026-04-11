# Simulator/simulator_builder_enhanced.py
"""
增强的仿真构建器 - 支持动态配置和实时监控
"""

import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime
from ns import ns

from Mobility.mobility import MobilityFactory
from Entity.UAV.PMAPUAV import PMAP_UAV
from Entity.ZSP.PMAPZSP import PMAP_ZSP
from BlockChain.Blockchain import Web3BlockchainAdapter
import copy


class SimulationBuilderEnhanced:
    """增强的仿真构建器"""
    
    def __init__(self, config_path=None, config_dict=None):
        """
        初始化仿真构建器
        
        Args:
            config_path: 配置文件路径
            config_dict: 配置字典
        """
        if config_path:
            self.config = self._load_json(config_path)
        elif config_dict:
            self.config = config_dict
        else:
            raise ValueError("Must provide config_path or config_dict")
        
        self.nodes = None
        self.uavs = []
        self.zsps = []
        
        # 初始化区块链
        self.blockchain = Web3BlockchainAdapter()
        
        # 统计信息
        self.stats = {
            "start_time": None,
            "end_time": None,
            "total_uavs": 0,
            "total_zsps": 0,
            "total_messages": 0,
            "successful_authentications": 0,
            "failed_authentications": 0
        }
        
        print("[BUILDER] SimulationBuilderEnhanced initialized")
    
    def _load_json(self, path):
        """加载配置文件"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)
            print(f"[BUILDER] Loaded config from {path}")
            return config
        except Exception as e:
            print(f"[BUILDER] JSON load error: {e}")
            raise
    
    def run(self):
        """运行仿真主流程"""
        try:
            print("[BUILDER] Starting simulation build and execution...")
            self.stats["start_time"] = datetime.now().isoformat()
            
            # 1. 创建节点
            self._create_nodes()
            
            # 2. 设置网络
            self._setup_network()
            
            # 3. 设置ZSP节点
            self._setup_zsp()
            
            # 4. 设置UAV节点
            self._setup_uav()
            
            # 5. 预注册
            self._pre_reg()
            
            # 6. 获取仿真时长
            duration = self.config.get("simulation", {}).get("duration", 30)
            
            # 7. 设置仿真停止时间
            ns.Simulator.Stop(ns.Seconds(duration))
            
            print(f"[BUILDER] Running simulation for {duration} seconds...")
            
            # 8. 运行仿真
            ns.Simulator.Run()
            
            # 9. 清理
            ns.Simulator.Destroy()
            
            self.stats["end_time"] = datetime.now().isoformat()
            self.stats["total_uavs"] = len(self.uavs)
            self.stats["total_zsps"] = len(self.zsps)
            
            print("[BUILDER] Simulation completed successfully")
            
            return {
                "status": "completed",
                "statistics": self.stats,
                "uav_count": len(self.uavs),
                "zsp_count": len(self.zsps)
            }
        
        except Exception as e:
            print(f"[BUILDER] Simulation failed: {e}")
            import traceback
            traceback.print_exc()
            
            self.stats["end_time"] = datetime.now().isoformat()
            
            return {
                "status": "failed",
                "error": str(e),
                "statistics": self.stats
            }
    
    def _create_nodes(self):
        """创建NS-3节点"""
        max_id = 0
        
        # 查找最大ID
        for u in self.config.get("uavs", []):
            max_id = max(max_id, u.get("id", 0))
        
        for z in self.config.get("zsps", []):
            max_id = max(max_id, z.get("id", 0))
        
        total = max_id + 1
        
        self.nodes = ns.NodeContainer()
        self.nodes.Create(total)
        
        print(f"[BUILDER] Created {total} nodes")
    
    def _setup_network(self):
        """设置网络协议栈"""
        stack = ns.InternetStackHelper()
        stack.Install(self.nodes)
        
        address = ns.Ipv4AddressHelper()
        address.SetBase(
            ns.Ipv4Address("10.1.1.0"),
            ns.Ipv4Mask("255.255.255.0")
        )
        
        channel = ns.CsmaHelper()
        channel_config = self.config.get("channel", {})
        channel.SetChannelAttribute(
            "DataRate",
            ns.StringValue(channel_config.get("datarate", "100Mbps"))
        )
        channel.SetChannelAttribute(
            "Delay",
            ns.TimeValue(ns.NanoSeconds(6560))
        )
        
        devices = channel.Install(self.nodes)
        interfaces = address.Assign(devices)
        
        print("[BUILDER] Network stack installed")
    
    def _setup_zsp(self):
        """设置ZSP节点"""
        for zsp_conf in self.config.get("zsps", []):
            node = self.nodes.Get(zsp_conf["id"])
            
            zsp = PMAP_ZSP(
                node,
                zsp_conf["id"],
                blockchain=self.blockchain,
                enable_blockchain=True
            )
            
            # 安装固定位置
            MobilityFactory.install_constant(
                node,
                zsp_conf.get("position", [0, 0, 100])
            )
            
            self.zsps.append(zsp)
            node.AddApplication(zsp)
            zsp.SetStartTime(ns.Seconds(0))
            
            print(f"[BUILDER] ZSP-{zsp_conf['id']} created")
    
    def _setup_uav(self):
        """设置UAV节点"""
        for uav_conf in self.config.get("uavs", []):
            node = self.nodes.Get(uav_conf["id"])
            
            # 安装移动模型
            MobilityFactory.install(
                node,
                uav_conf.get("mobility", {})
            )
            
            # 创建UAV应用
            uav = PMAP_UAV(node, uav_conf["id"])
            
            self.uavs.append(uav)
            node.AddApplication(uav)
            uav.SetStartTime(ns.Seconds(0))
            
            print(f"[BUILDER] UAV-{uav_conf['id']} created")
    
    def _pre_reg(self):
        """预注册所有UAV到ZSP"""
        for uav in self.uavs:
            reg = {
                "uav_id": uav.id,
                "crp": uav.crp,
                "pid": uav.pid
            }
            
            for zsp in self.zsps:
                zsp.RegisterUAV(uav.pid, copy.deepcopy(reg))
        
        print(f"[BUILDER] Pre-registered {len(self.uavs)} UAVs")


if __name__ == "__main__":
    import sys
    
    config_file = os.getenv("CONFIG_FILE", "config.json")
    
    if not os.path.exists(config_file):
        print(f"[ERROR] Config file not found: {config_file}")
        sys.exit(1)
    
    builder = SimulationBuilderEnhanced(config_path=config_file)
    result = builder.run()
    
    print("\n" + "="*60)
    print("SIMULATION RESULT SUMMARY")
    print("="*60)
    print(json.dumps(result, indent=2, default=str))
    print("="*60)
    
    sys.exit(0 if result["status"] == "completed" else 1)