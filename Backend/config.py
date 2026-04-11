# Backend/config.py
"""
后端配置文件
"""

import os
from pathlib import Path


class Config:
    """基础配置类"""
    
    # 应用配置
    APP_NAME = "UAV D2Z Authentication Simulation Platform"
    APP_VERSION = "1.0.0"
    DEBUG = False
    
    # 项目根目录
    PROJECT_ROOT = Path(__file__).parent.parent
    
    # 日志目录配置 - 与仿真器输出日志的目录一致
    LOG_DIR = "/home/zhang/UAV/logs"
    
    @staticmethod
    def get_log_dir():
        """获取日志目录"""
        log_dir = "/home/zhang/UAV/logs"
        os.makedirs(log_dir, exist_ok=True)
        return log_dir
    
    # 仿真任务目录
    SIMULATION_TASKS_DIR = os.path.expanduser("~/UAV_Simulation/tasks")
    
    # NS-3 仿真器相关配置
    NS3_INSTALL_PATH = os.path.expanduser("~/ns/ns-allinone-3.43/ns-3.43")
    NS3_COMMAND = os.path.expanduser("~/ns/ns-allinone-3.43/ns-3.43/ns3")
    SIMULATOR_SCRIPT = "/home/zhang/UAV/simulator_builder.py"
    
    # API 配置
    API_V1_PREFIX = "/api/v1"
    CORS_ORIGINS = ["*"]
    
    # 缓存配置
    CACHE_MAX_EVENTS = 10000
    CACHE_UPDATE_INTERVAL = 1  # 秒
    
    # 页面大小
    DEFAULT_PAGE_SIZE = 100
    MAX_PAGE_SIZE = 1000


class DevelopmentConfig(Config):
    """开发配置"""
    DEBUG = True


class ProductionConfig(Config):
    """生产配置"""
    DEBUG = False


def get_config():
    """获取当前配置"""
    env = os.getenv("ENV", "development")
    if env == "production":
        return ProductionConfig()
    return DevelopmentConfig()


config = get_config()