import secrets
import hashlib
from ecdsa import NIST256p
from ecdsa.ellipticcurve import Point
import binascii

class ChameleonHashCalculator():

    def __init__(self, key_size: int = 256):
        self.curve = NIST256p
        self.generator = self.curve.generator
        self.order = self.curve.order
        self.public_key = None
        self.private_key = None

    def generate_key_pair(self):
        # Placeholder implementation for PUF-based key generation
        self.private_key = secrets.token_hex(32)
        self.public_key = self.generate_public_key_by_private_key(self.private_key)
        return self.private_key, self.public_key

    def get_public_params(self):
        # Placeholder implementation for retrieving public parameters
        return self.public_key
    
    def serialize_point(self, point: Point) -> str:
        """将椭圆曲线点序列化为十六进制字符串 (非压缩格式)"""
        return binascii.hexlify(point.to_bytes()).decode()
    
    def deserialize_point(self, data: str) -> Point:
        """从十六进制字符串恢复椭圆曲线点"""
        byte_data = binascii.unhexlify(data)
        return Point.from_bytes(self.curve.curve, byte_data)

    def generate_public_key_by_private_key(self, private_key: str) -> str:
        # Placeholder implementation for generating public key from private key
        priv_int = int(private_key, 16) % self.order
        pub_point = priv_int * self.generator
        return self.serialize_point(pub_point)
    
    def get_private_key_value_from_hash(self, *args) -> int:
        """将输入数据映射为标量场 Zq 上的整数"""
        payload = "".join(str(a) for a in args).encode()
        return int(hashlib.sha256(payload).hexdigest(), 16) % self.order
        
    def caculate_hash_kef(self, Y: Point, m: int, r: int, pk_point: Point) -> str:
        """
        验证者端实现：CH = m*G + r*Y + Pk
        """
        term1 = (m % self.order) * self.generator
        term2 = (r % self.order) * Y
        res_point = term1 + term2 + pk_point
        
        # 序列化结果点坐标进行最终哈希
        data = f"{res_point.x()}{res_point.y()}".encode()
        return hashlib.sha256(data).hexdigest()
    
    def find_collision(self, R_puf: int, m_old: int, r_old: int, tk_old: int, m_new: int, tk_new: int) -> int:
        """
        无人机端实现：计算碰撞随机数 r_new
        公式: r_new = [(m_old - m_new) + (tk_old - tk_new)] * R^-1 + r_old (mod q)
        """
        r_inv = pow(R_puf, -1, self.order)
        delta_m = (m_old - m_new) % self.order
        delta_tk = (tk_old - tk_new) % self.order
        return ((delta_m + delta_tk) * r_inv + r_old) % self.order