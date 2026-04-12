"""
与链上 UAVRegistry.updatePID 一致的 CRP 浮点 ↔ uint256 编解码。

链上使用固定缩放写入 uint256，各 ZSP 从事件解码后必须与 UAV 本地使用的
CRP 完全一致，否则多 ZSP 场景下会出现 M1 MAC 校验失败。
"""

from __future__ import annotations

# 须与 BlockChain/Blockchain.py 中历史实现保持一致
CRP_CHAIN_SCALE = 10**12


def crp_to_uint(value: float) -> int:
    return int(value * CRP_CHAIN_SCALE)


def uint_to_crp(value: int) -> float:
    return value / CRP_CHAIN_SCALE


def canonicalize_scalar(value: float) -> float:
    """与链上 updatePID / 事件往返等价的浮点值。"""
    return uint_to_crp(crp_to_uint(value))


def canonicalize_crp_pair(challenge: float, response: float) -> tuple[float, float]:
    return canonicalize_scalar(challenge), canonicalize_scalar(response)
