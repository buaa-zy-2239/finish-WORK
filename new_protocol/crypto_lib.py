import hashlib, hmac
from Crypto.Cipher import AES
from ecdsa import SigningKey, SECP256k1


# =========================
# PUF
# =========================
class SimulatedIdealPUF:
    def __init__(self, hardware_seed: bytes):
        self.__hw_secret = hardware_seed

    def evaluate(self, challenge: str) -> bytes:
        return hmac.new(self.__hw_secret, challenge.encode(), hashlib.sha256).digest()


# =========================
# Chameleon Hash
# =========================
class ChameleonHash:
    def __init__(self):
        self.curve = SECP256k1
        self.generator = self.curve.generator
        self.order = self.curve.order

    def generate_keypair(self, seed_r: bytes):
        sk_int = int.from_bytes(seed_r, "big") % self.order
        sk = SigningKey.from_secret_exponent(sk_int, curve=self.curve)
        return sk, sk.get_verifying_key()

    def calculate(self, pk, message: str, r: int, s: int) -> str:
        m_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        point = (m_hash * self.generator) + (r * pk.pubkey.point) + (s * self.generator)
        return hashlib.sha256(f"{point.x()}{point.y()}".encode()).hexdigest()

    def find_collision(self, sk, m_old: str, r_old: int, s_old: int, m_new: str):
        m_old_h = int(hashlib.sha256(m_old.encode()).hexdigest(), 16)
        m_new_h = int(hashlib.sha256(m_new.encode()).hexdigest(), 16)
        s_new = (m_old_h - m_new_h + s_old) % self.order
        return r_old, s_new


# =========================
# KDF
# =========================
def kdf(key: bytes, msg_list: list) -> bytes:
    content = b"".join(
        m.encode() if isinstance(m, str) else m for m in msg_list
    )
    return hmac.new(key, content, hashlib.sha256).digest()


# =========================
# AES-GCM（关键修复：外部传入 nonce）
# =========================
def aes_gcm_encrypt(key: bytes, nonce_hex: str, plaintext: str, ad: str):
    nonce = bytes.fromhex(nonce_hex)
    cipher = AES.new(key[:16], AES.MODE_GCM, nonce=nonce)
    cipher.update(ad.encode())
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return ciphertext.hex(), tag.hex()


def aes_gcm_decrypt(key: bytes, nonce_hex: str, ciphertext_hex: str, tag_hex: str, ad: str):
    try:
        nonce = bytes.fromhex(nonce_hex)
        cipher = AES.new(key[:16], AES.MODE_GCM, nonce=nonce)
        cipher.update(ad.encode())
        pt = cipher.decrypt_and_verify(bytes.fromhex(ciphertext_hex), bytes.fromhex(tag_hex))
        return True, pt.decode()
    except Exception:
        return False, None