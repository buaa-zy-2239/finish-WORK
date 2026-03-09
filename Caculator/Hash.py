import hashlib

def hash_256(data: str) -> str:
    """ 计算 SHA-256 哈希值 """
    sha256 = hashlib.sha256()
    sha256.update(data.encode('utf-8'))
    return sha256.hexdigest()