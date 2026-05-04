"""
PMAP协议公共模块 - 提供PMAP协议的共享工具和会话类
"""

import hashlib
import struct
import uuid


def d2z_mac_hex(payload_bytes: bytes, params) -> str:
    """计算D2Z消息认证码"""
    mac_input = payload_bytes
    for p in params:
        mac_input += p
    return hashlib.sha256(mac_input).hexdigest()


class D2D_Session:
    """D2D会话状态"""
    
    def __init__(self):
        self.ni = None
        self.nj = None
        self.n1 = None
        self.n2 = None
        self.session_key = None


class D2Z_Session:
    """D2Z会话状态"""
    
    def __init__(self):
        self.ni = None
        self.ns = None
        self.from_addr = None
        self.session_key = None
        self.zsp_session_id = str(uuid.uuid4())
        self.subsession_id = None
        self.auth_session_id = None


class PMAPMacHelper:
    """PMAP MAC验证辅助类"""
    
    @staticmethod
    def verify_mac(payload: bytes, params: list, mac: str) -> bool:
        """验证MAC"""
        mac_input = payload
        for p in params:
            mac_input += p
        expected = hashlib.sha256(mac_input).hexdigest()
        return expected == mac


__all__ = [
    "d2z_mac_hex",
    "D2D_Session",
    "D2Z_Session",
    "PMAPMacHelper",
]