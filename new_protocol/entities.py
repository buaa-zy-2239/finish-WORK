import time, secrets, json
from crypto_lib import *


# =========================
# UAV
# =========================
class UAV:
    def __init__(self, uav_id: str, hw_seed: bytes):
        self.uav_id = uav_id
        self.puf = SimulatedIdealPUF(hw_seed)
        self.ch = ChameleonHash()

        self.current_C = None
        self.idx = None

        self.m_anchor = "anchor_init"
        self.r_anchor = 0x1111
        self.s_anchor = 0x2222

    def set_initial_challenge(self, c_init: str):
        self.current_C = c_init

    def generate_m1(self, message: str) -> str:
        t_u = str(int(time.time()))
        nonce_u = secrets.token_hex(8)

        R = self.puf.evaluate(self.current_C)

        sk, pk = self.ch.generate_keypair(R)

        m_eval = message + t_u

        r, s = self.ch.find_collision(
            sk,
            self.m_anchor,
            self.r_anchor,
            self.s_anchor,
            m_eval
        )

        ad = f"{message}{r}{s}{t_u}{nonce_u}"
        tag = kdf(R, [ad]).hex()

        return json.dumps({
            "idx": self.idx,
            "m": message,
            "r": r,
            "s": s,
            "t": t_u,
            "nonce": nonce_u,
            "tag": tag
        })

    def process_m2(self, m2_json: str, nonce_u: str):
        m2 = json.loads(m2_json)

        R = self.puf.evaluate(self.current_C)

        # ⭐关键：与 GBS 完全一致
        key = kdf(R, [nonce_u, m2["nonce"]])

        ok, next_C = aes_gcm_decrypt(
            key,
            m2["nonce"],
            m2["ct"],
            m2["tag"],
            m2["nonce"]
        )

        if ok:
            self.current_C = next_C
            return True
        return False


# =========================
# GBS
# =========================
class GBS:
    def __init__(self):
        self.ch = ChameleonHash()
        self.db = {}
        self.crp_pool = {}

    def enroll_uav(self, uav: UAV, num_crps=50):
        crps = {}

        for _ in range(num_crps):
            c = secrets.token_hex(16)
            r = uav.puf.evaluate(c)
            crps[c] = r

        self.crp_pool[uav.uav_id] = crps

        c0 = list(crps.keys())[0]
        r0 = crps[c0]

        uav.set_initial_challenge(c0)

        sk, pk = self.ch.generate_keypair(r0)

        idx = self.ch.calculate(pk, uav.m_anchor, uav.r_anchor, uav.s_anchor)

        uav.idx = idx

        self.db[idx] = {
            "uav_id": uav.uav_id,
            "cur_C": c0,
            "bak_C": c0,
            "pk": pk
        }

        return idx

    def process_m1(self, m1_json: str):
        m1 = json.loads(m1_json)

        if abs(time.time() - int(m1["t"])) > 30:
            return None

        idx = m1["idx"]
        if idx not in self.db:
            return None

        rec = self.db[idx]
        uav_id = rec["uav_id"]

        # CH 验证
        m_eval = m1["m"] + m1["t"]
        if self.ch.calculate(rec["pk"], m_eval, m1["r"], m1["s"]) != idx:
            return None

        ad = f"{m1['m']}{m1['r']}{m1['s']}{m1['t']}{m1['nonce']}"

        R_cur = self.crp_pool[uav_id][rec["cur_C"]]
        R_bak = self.crp_pool[uav_id][rec["bak_C"]]

        if kdf(R_cur, [ad]).hex() == m1["tag"]:
            return {"rec": rec, "R": R_cur, "is_bak": False, "nonce_u": m1["nonce"]}

        if kdf(R_bak, [ad]).hex() == m1["tag"]:
            return {"rec": rec, "R": R_bak, "is_bak": True, "nonce_u": m1["nonce"]}

        return None

    def generate_m2(self, session):
        rec = session["rec"]
        uav_id = rec["uav_id"]

        pool = self.crp_pool[uav_id]
        available = [c for c in pool if c not in (rec["cur_C"], rec["bak_C"])]
        next_C = secrets.choice(available)

        # ⭐唯一 nonce（用于 KDF + AEAD + AD）
        nonce = secrets.token_bytes(12).hex()

        key = kdf(session["R"], [session["nonce_u"], nonce])

        ct, tag = aes_gcm_encrypt(
            key,
            nonce,
            next_C,
            nonce
        )

        if session["is_bak"]:
            rec["cur_C"] = next_C
        else:
            rec["bak_C"] = rec["cur_C"]
            rec["cur_C"] = next_C

        return json.dumps({
            "nonce": nonce,
            "ct": ct,
            "tag": tag
        })