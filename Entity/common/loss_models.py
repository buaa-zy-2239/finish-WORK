"""
丢包模型模块 - 提供上行/下行链路丢包计算
"""

import math
import random
from typing import Dict, Any


class BurstLossModel:
    """突发丢包模型 (Gilbert-Elliott模型)"""

    def __init__(self, config: Dict[str, Any] = None):
        config = config or {}
        self.enabled = bool(config.get("enabled", False))
        self.p_good_to_bad = max(0.0, min(1.0, float(config.get("p_good_to_bad", 0.02))))
        self.p_bad_to_good = max(0.0, min(1.0, float(config.get("p_bad_to_good", 0.25))))
        self.loss_good = max(0.0, min(1.0, float(config.get("loss_good", 0.02))))
        self.loss_bad = max(0.0, min(1.0, float(config.get("loss_bad", 0.75))))
        self._in_bad_state = False

    def get_loss_rate(self) -> float:
        """获取当前丢包率"""
        if not self.enabled:
            return 0.0

        if self._in_bad_state:
            if random.random() < self.p_bad_to_good:
                self._in_bad_state = False
        else:
            if random.random() < self.p_good_to_bad:
                self._in_bad_state = True

        return self.loss_bad if self._in_bad_state else self.loss_good

    def should_drop(self) -> bool:
        """判断是否应该丢包"""
        return random.random() < self.get_loss_rate()


