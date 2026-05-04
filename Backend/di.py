"""
依赖注入模块 - 统一服务管理
"""

from typing import Any, Dict, Type
from threading import Lock


class ServiceContainer:
    """服务容器（单例）"""
    
    _instance = None
    _lock = Lock()
    _services: Dict[str, Any] = {}
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def register(self, name: str, service: Any) -> None:
        """注册服务"""
        self._services[name] = service
    
    def get(self, name: str) -> Any:
        """获取服务"""
        service = self._services.get(name)
        if service is None:
            raise ValueError(f"Service '{name}' not registered")
        return service
    
    def has(self, name: str) -> bool:
        """检查服务是否已注册"""
        return name in self._services
    
    def clear(self) -> None:
        """清空所有服务"""
        self._services.clear()


class ServiceProvider:
    """服务提供者基类"""
    
    def register(self, container: ServiceContainer) -> None:
        """注册服务到容器"""
        pass
    
    def boot(self, container: ServiceContainer) -> None:
        """启动服务"""
        pass


class LogServiceProvider(ServiceProvider):
    """日志服务提供者"""
    
    def register(self, container: ServiceContainer) -> None:
        from services.log_service import LogService
        container.register('log_service', LogService())
    
    def boot(self, container: ServiceContainer) -> None:
        log_service = container.get('log_service')
        log_service.load_logs(force_reload=True)


class SimulationServiceProvider(ServiceProvider):
    """仿真服务提供者"""
    
    def register(self, container: ServiceContainer) -> None:
        from services.simulation_service import SimulationService
        container.register('simulation_service', SimulationService())


def create_container() -> ServiceContainer:
    """创建并初始化服务容器"""
    container = ServiceContainer()
    
    providers = [
        LogServiceProvider(),
        SimulationServiceProvider(),
    ]
    
    for provider in providers:
        provider.register(container)
    
    for provider in providers:
        provider.boot(container)
    
    return container


def get_service(name: str) -> Any:
    """获取服务（便捷方法）"""
    container = ServiceContainer()
    return container.get(name)


# 全局服务容器
container = create_container()