# 在 Backend/core/event_models.py 末尾添加

from pydantic import BaseModel
from typing import List, Optional


class UAVConfig(BaseModel):
    """UAV 配置"""
    id: int
    mobility: dict


class ZSPConfig(BaseModel):
    """ZSP 配置"""
    id: int
    position: List[float]


class ChannelConfig(BaseModel):
    """通道配置"""
    type: str = "CSMA"
    datarate: str = "100Mbps"
    delay: str = "6560ns"


class SimulationTaskDTO(BaseModel):
    """仿真任务数据传输对象"""
    name: str
    description: Optional[str] = ""
    duration: int = 30
    uavs: List[UAVConfig] = []
    zsps: List[ZSPConfig] = []
    protocol: str = "PMAP"
    channel: ChannelConfig = ChannelConfig()