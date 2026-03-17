import struct
import random
import hashlib

from Entity.ZSP.BaseZSP import BaseZSP
from Caculator.ChaoticMap import ChaoticMap
from Caculator.Hash import hash_256
from Protocol.PMAP.PMAPPlaintext import PMAPPlaintext as PMAP
from Protocol.PMAP.Packet import PMAPPacket
from Protocol.PMAP.MsgType import PMAPMessageType


class D2Z_Session:
    def __init__(self):
        self.ni = None
        self.ns = None
        self.from_addr = None
        self.session_key = None


class D2D_Session:
    def __init__(self):
        self.ni = None
        self.nj = None
        self.n1 = None
        self.n2 = None
        self.from_addr = None
        self.to_addr = None


class PMAP_ZSP(BaseZSP):

    def __init__(self, node, zsp_id, blockchain=None, enable_blockchain=True):

        super().__init__(node, zsp_id, blockchain, enable_blockchain)

        self.chaotic = ChaoticMap()

        self.D2Z_sessions = {}
        self.D2D_sessions = {}

        self.crp = [None, None]

    # =========================================================
    # MAC
    # =========================================================

    def verify_mac(self, payload, params, mac):
        mac_input = payload
        for p in params:
            mac_input += p
        expected = hashlib.sha256(mac_input).hexdigest()
        return expected == mac

    # =========================================================
    # 接收处理
    # =========================================================

    def ProcessRequest(self, buf, from_addr):
        msg_type,pid,payload, mac = PMAPPacket.parse(buf)

        if msg_type == PMAPMessageType.M1:
            self.handle_M1(pid,payload, mac, from_addr)

        elif msg_type == PMAPMessageType.M3_4:
            self.handle_M3_4(pid,payload, mac, from_addr)

        elif msg_type == PMAPMessageType.D2D_M1_2:
            self.handle_D2D_M1_2(pid,payload, mac, from_addr)

        elif msg_type == PMAPMessageType.D2D_M4_5:
            self.handle_D2D_M4_5(pid,payload, mac, from_addr)
        elif msg_type == PMAPMessageType.D2D_M9_10:
            self.handle_D2D_M9_10(pid,payload, mac, from_addr)

    # =========================================================
    # M1
    # =========================================================

    def handle_M1(self, pid, payload, mac, from_addr):

        if pid not in self.uav_db:
            print(f"[ZSP-{self.zsp_id}] Unknown PID")
            return

        crp = self.uav_db[pid]["crp"]
        decrypted = self.chaotic.decrypt_by_crp(payload, crp)
        m1 = PMAP.decode(PMAP.M1,decrypted)
        ni = m1[2]
        if not self.verify_mac(payload, [struct.pack(">d", ni)], mac):
            print(f"[ZSP-{self.zsp_id}] M1 MAC fail")
            return

        print(f"[ZSP-{self.zsp_id}] M1 verified")

        ns = random.random()

        session = D2Z_Session()
        session.ni = ni
        session.ns = ns
        session.from_addr = from_addr

        self.D2Z_sessions[pid] = session

        plaintext = bytes.fromhex(pid) + struct.pack(">I", self.zsp_id) + struct.pack(">d", ni) + struct.pack(">d", ns)

        encrypted = self.chaotic.encrypt_by_crp(plaintext, crp)

        mac = hashlib.sha256(encrypted + struct.pack(">d", session.ni) + struct.pack(">d", ns)).hexdigest()

        packet = PMAPPacket.build(
            PMAPMessageType.M2,
            pid,
            encrypted,
            encrypted + struct.pack(">d", session.ni) + struct.pack(">d", ns)
        )

        self.SendResponse(packet, from_addr)

    # =========================================================
    # M3
    # =========================================================

    def handle_M3_4(self, pid, payload, mac, from_addr):

        if pid not in self.uav_db:
            return

        crp = self.uav_db[pid]["crp"]

        m3_size = PMAP.M3.size
        m4_size = PMAP.M4.size
        enc3 = payload[:m3_size]
        enc4 = payload[m3_size:m3_size + m4_size]

        plain3 = self.chaotic.decrypt_by_crp(enc3, crp)
        plain4 = self.chaotic.decrypt_by_crp(enc4, crp)

        m3 = PMAP.decode(PMAP.M3, plain3)
        m4 = PMAP.decode(PMAP.M4, plain4)

        ni = m3[3]
        response = m4[4]
        session = self.D2Z_sessions[pid]
        session.ni = ni 
        session_key = int(hash_256(str(ni)), 16) ^ \
                      int(hash_256(str(session.ns)), 16)

        session.session_key = session_key

        print(f"[ZSP-{self.zsp_id}] Session key established is {hex(session_key)}")
        if not self.verify_mac(payload, [struct.pack(">d", session.ni), struct.pack(">d", response)], mac):
            print(f"[ZSP-{self.zsp_id}] M3_4 MAC fail")
            return
        seed = self.chaotic.encrypt_by_crp(str(session.ni).encode() + str(session.ns).encode(), crp)
        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        new_pid = hash_256(str(self.uav_db[pid]["uav_id"]) + str(response))
        self.UpdateUAVPID(pid, new_pid, challenge, response)
        self.uav_db[new_pid]["crp"] = [challenge, response]
        self.D2Z_sessions[new_pid] = self.D2Z_sessions.pop(pid)
        
    # =========================================================
    # D2D M1_2
    # =========================================================

    def handle_D2D_M1_2(self, pid, payload, mac, from_addr):
        if pid not in self.uav_db:
            print("invalid pid")
            return

        m1_size = PMAP.D2D_M1.size
        m2_size = PMAP.D2D_M2.size
        enc1 = payload[:m1_size]
        enc2 = payload[m1_size:m1_size + m2_size]
        plain1 = self.chaotic.decrypt_by_crp(enc1, self.uav_db[pid]["crp"])
        plain2 = self.chaotic.decrypt_by_crp(enc2, self.uav_db[pid]["crp"])
        m1 = PMAP.decode(PMAP.D2D_M1, plain1)
        m2 = PMAP.decode(PMAP.D2D_M2, plain2)
        pid_j = m2[3]
        ni = m1[2]

        if not self.verify_mac(payload, [struct.pack(">d", ni),struct.pack(">32s", bytes.fromhex(pid_j))], mac):
            print(f"[ZSP-{self.zsp_id}] M1 MAC fail")
            return 
        session = D2D_Session()
        session.ni = ni
        session.n1 = random.random()
        session.n2 = random.random()
        session.from_addr = from_addr
        session.to_addr = self.D2Z_sessions[pid_j].from_addr
        self.D2D_sessions[pid+pid_j] = session
        m3 = PMAP.encode(
            PMAP.D2D_M3,
            pid,
            self.zsp_id,
            pid_j,
            ni,
            session.n1
        )
        encrypted = self.chaotic.encrypt_by_crp(
            m3,
            self.uav_db[pid]["crp"]
        )

        mac_input = encrypted + struct.pack(">d", ni) + struct.pack(">d", session.n1)
        
        packet = PMAPPacket.build(
            PMAPMessageType.D2D_M3,
            pid,
            encrypted,
            mac_input
        )

        self.SendResponse(packet, from_addr)
       
        

    # =========================================================
    # D2D M4
    # =========================================================

    def handle_D2D_M4_5(self, pid, payload, mac, from_addr):

        if pid not in self.uav_db:
            return

        m4_size = PMAP.D2D_M4.size
        m5_size = PMAP.D2D_M5.size
        enc4 = payload[:m4_size]
        enc5 = payload[m4_size:m4_size + m5_size]
        plain4 = self.chaotic.decrypt_by_crp(enc4, self.uav_db[pid]["crp"])
        plain5 = self.chaotic.decrypt_by_crp(enc5, self.uav_db[pid]["crp"])
        m4 = PMAP.decode(PMAP.D2D_M4, plain4)
        m5 = PMAP.decode(PMAP.D2D_M5, plain5)
        pid_j = m4[2]
        ni = m4[4]
        response = m5[5]

        if not self.verify_mac(payload, [struct.pack(">d", ni),struct.pack(">d", response)], mac):
            print(f"[ZSP-{self.zsp_id}] M4_5 MAC fail")
            return 
        session = self.D2D_sessions[pid+pid_j]
        session.ni = ni
        m6 = PMAP.encode(
            PMAP.D2D_M6,
            pid_j,
            self.zsp_id,
            session.n2
        )
        
        m7 = PMAP.encode(
            PMAP.D2D_M7,
            pid_j,
            self.zsp_id,
            session.n2,
            ni
        )
        m8 = PMAP.encode(
            PMAP.D2D_M8,
            pid_j,
            self.zsp_id,
            session.n2,
            ni,
            pid
        )
        
        uav_data = self.uav_db[pid_j]["crp"]
        encrypted_6 = self.chaotic.encrypt_by_crp(m6, uav_data)
        encrypted_7 = self.chaotic.encrypt_by_crp(m7, uav_data)
        encrypted_8 = self.chaotic.encrypt_by_crp(m8, uav_data)

        encrypted = encrypted_6 + encrypted_7 + encrypted_8
        mac_input = encrypted + struct.pack(">d", session.n2) + struct.pack(">d", session.ni)
        
        packet = PMAPPacket.build(
            PMAPMessageType.D2D_M6_7_8,
            pid_j,
            encrypted,
            mac_input
        )

        self.SendResponse(packet, session.to_addr)
        

        seed = self.chaotic.encrypt_by_crp(
                str(session.n1).encode() + str(session.ni).encode(),
                self.uav_db[pid]["crp"]
        )
        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        self.crp = [challenge,response]


    # =========================================================
    # D2D M9
    # =========================================================

    def handle_D2D_M9_10(self, pid, payload, mac, from_addr):

        if pid not in self.uav_db:
            return

        m9_size = PMAP.D2D_M9.size
        m10_size = PMAP.D2D_M10.size
        enc9 = payload[:m9_size]
        enc10 = payload[m9_size:m9_size + m10_size]
        plain9 = self.chaotic.decrypt_by_crp(enc9, self.uav_db[pid]["crp"])
        plain10 = self.chaotic.decrypt_by_crp(enc10, self.uav_db[pid]["crp"])
        m9 = PMAP.decode(PMAP.D2D_M9, plain9)
        m10 = PMAP.decode(PMAP.D2D_M10, plain10)
        pid_i = m9[2]
        nj = m9[4]
        response = m10[5]

        if not self.verify_mac(payload, [struct.pack(">d", nj),struct.pack(">d", response)], mac):
            print(f"[ZSP-{self.zsp_id}] M9_10 MAC fail")
            return 
        session = self.D2D_sessions[pid_i+pid]
        session.nj = nj
        m11 = PMAP.encode(
            PMAP.D2D_M11,
            pid_i,
            self.zsp_id,
            pid,
            session.ni,
            session.nj
        )
        encrypted = self.chaotic.encrypt_by_crp(
            m11,
            self.uav_db[pid_i]["crp"]
        )

        mac_input = encrypted + struct.pack(">d", session.ni) + struct.pack(">d", session.nj)
        session_key = int(hash_256(str(session.ni)), 16) ^ \
            int(hash_256(str(session.nj)), 16)
        session.session_key = session_key
        print(f"[ZSP-{self.zsp_id}] D2D Session key established is {hex(session_key)}")

        packet = PMAPPacket.build(
            PMAPMessageType.D2D_M11,
            pid_i,
            encrypted,
            mac_input
        )

        self.SendResponse(packet, session.from_addr)
        seed = self.chaotic.encrypt_by_crp(
                str(session.n2).encode() + str(session.nj).encode(),
                self.crp
            )

        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        new_pid = hash_256(str(self.uav_db[pid]["uav_id"]) + str(response))
        self.UpdateUAVPID(pid, new_pid, challenge, response)

        new_pid = hash_256(str(self.uav_db[pid_i]["uav_id"]) + str(self.crp[1]))
        self.UpdateUAVPID(pid_i, new_pid, self.crp[0], self.crp[1])

