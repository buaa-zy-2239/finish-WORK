# security_modules/key_generation/ecc_keygen.py
import time
from ecdsa import SigningKey, NIST256p, SECP256k1
from BaseKeyGenerator import BaseKeyGenerator

class ECCKeyGenerator(BaseKeyGenerator):
    """
    使用 python-ecdsa 库实现的 ECC 密钥生成模块。
    """
    def __init__(self, security_param: int = 128, curve_name: str = "NIST256p"):
        super().__init__(security_param)
        # 根据安全参数选择曲线
        # NIST256p 提供约 128-bit 安全强度
        if curve_name == "NIST256p":
            self.curve = NIST256p
        elif curve_name == "SECP256k1": # 比特币使用的曲线
            self.curve = SECP256k1
        else:
            self.curve = NIST256p
            
        self.private_key = None # SigningKey 对象 (私钥)
        self.public_key = None # VerifyingKey 对象 (公钥)

    def generate_key_pair(self):
        """
        生成 ECC 公私钥对
        """
        start_time = time.perf_counter()
        
        # 1. 生成私钥 (Signing Key)
        self.private_key = SigningKey.generate(curve=self.curve)
        
        # 2. 导出对应的公钥 (Verifying Key)
        self.public_key = self.private_key.verifying_key
        
        # 转换为字节流用于仿真传输
        self.private_key = self.private_key.to_string() # 原始私钥字节
        self.public_key = self.public_key.to_string()   # 原始公钥字节 (通常为 64 字节)
        
        self.gen_time = (time.perf_counter() - start_time) * 1000 # 毫秒
        return self.public_key, self.private_key

    def get_public_params(self):
        return {
            "tech": "ECDSA",
            "curve": self.curve.name,
            "pk_hex": self.public_key.hex() if self.public_key else None,
            "pk_size_bytes": len(self.public_key) if self.public_key else 0
        }

    def sign(self, message: bytes):
        """
        使用私钥对消息签名 (用于认证阶段仿真)
        """
        if self.private_key:
            return self.private_key.sign(message)
        return None

    def verify(self, signature: bytes, message: bytes, pub_key_bytes: bytes):
        """
        使用公钥验证签名
        """
        from ecdsa import VerifyingKey
        vk = VerifyingKey.from_string(pub_key_bytes, curve=self.curve)
        try:
            return vk.verify(signature, message)
        except:
            return False
        