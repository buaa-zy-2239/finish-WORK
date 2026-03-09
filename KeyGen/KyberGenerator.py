from BaseKeyGenerator import BaseKeyGenerator
from Crypto.PublicKey import Kyber
class KyberGenerator(BaseKeyGenerator):
    def __init__(self, key_size: int = 256):
        """ 初始化Kyber密钥生成器 """
        super().__init__(key_size)

    def generate_key_pair(self):
        """ 模拟Kyber密钥对生成逻辑 """
        key=Kyber.generate(degree=512)  # 使用Kyber-512
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()
        return self.private_key, self.public_key
    
    def get_public_params(self):
        """ 返回Kyber公钥 """
        return self.public_key

if __name__ == "__main__":
    kyber_gen = KyberGenerator()
    priv_key, pub_key = kyber_gen.generate_key_pair()
    print("Private Key:", priv_key)
    print("Public Key:", pub_key)