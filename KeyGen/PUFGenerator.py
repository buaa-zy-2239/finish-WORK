from KeyGen.BaseKeyGenerator import BaseKeyGenerator
import hashlib
class PUFGenerator(BaseKeyGenerator):
    def __init__(self, uav_id: str):
        """ 初始化PUF生成器 """
        super().__init__()
        self.uav_id = uav_id
        self.challenge=None

    def generate_response(self, challenge: float) -> str:
        """ 模拟PUF响应生成逻辑 """
        self.challenge=challenge
        combined = f"{self.uav_id}:{challenge}"
        response = hashlib.sha256(combined.encode()).hexdigest()
        return int(response[:13], 16)/(16**13)  # 将前13个十六进制字符转换为浮点数
    
    def generate_key_pair(self):
        """PUF不生成传统意义上的密钥对"""
        pass  

    def get_public_params(self):
        """单独使用PUF方案,只需要返回challenge"""
        return self.challenge
    