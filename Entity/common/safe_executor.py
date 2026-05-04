"""
安全执行器模块 - 提供容错执行和调度功能
"""

import cppyy
from collections import deque
from typing import Callable, Any


class SafeExecutor:
    """安全执行器Mixin - 提供容错执行和调度功能"""

    _CAP = 262144

    def _init_safe_executor(self):
        """初始化安全执行器"""
        self._event_refs = deque(maxlen=self._CAP)
        self.error_count = 0
        self.max_errors = 50

    def _safe_execute(self, tag: str, func: Callable, *args) -> Any:
        """安全执行函数，捕获异常并计数"""
        try:
            return func(*args)
        except Exception as e:
            self.error_count += 1
            return None

    def _safe_schedule(self, delay_sec: float, func: Callable, *args) -> None:
        """安全调度函数，在指定延迟后执行"""
        from ns import ns

        def wrapper():
            self._safe_execute(func.__name__, func, *args)

        event_cb = cppyy.gbl.std.function['void()'](wrapper)
        self._event_refs.append(wrapper)
        self._event_refs.append(event_cb)
        ns.Simulator.Schedule(ns.Seconds(delay_sec), event_cb)