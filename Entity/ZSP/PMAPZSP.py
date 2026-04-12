import struct
import random
import hashlib
from typing import Optional

from Common.logging_framework import (
    AuthenticationPhase, DatabaseOperation, IdentifierOperation
)
from Common.crp_chain_codec import canonicalize_crp_pair
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

    def __init__(
        self,
        node,
        zsp_id,
        blockchain=None,
        enable_blockchain=True,
        attack_model=None,
        d2z_ack_mode: bool = False,
    ):

        super().__init__(node, zsp_id, blockchain, enable_blockchain)

        self.attack_model = attack_model if attack_model is not None else {}
        self.d2z_ack_mode = bool(d2z_ack_mode)

        self.chaotic = ChaoticMap()

        self.D2Z_sessions = {}
        self.D2D_sessions = {}

        self.crp = [None, None]

        # 去同步：每 UAV 仅消耗一次「丢 M3/M4」与一次「拦 D2Z_ACK」（见 desync_attack_first_auth_only）
        self._desync_m3m4_drop_uavs = set()
        self._desync_ack_suppress_uavs = set()
        self._desync_m3m4_anonymous_drop_used = False
        self._desync_ack_anonymous_suppress_used = False

    def _desync_first_auth_only(self) -> bool:
        return bool(self.attack_model.get("desync_attack_first_auth_only", False))

    def _consume_m3m4_drop_desync(self, pid: str) -> bool:
        """若本包应按去同步模型丢弃，返回 True。"""
        if not self.attack_model.get("intercept_m3_m4_delivery"):
            return False
        if not self._desync_first_auth_only():
            return True
        uid = self.uav_db.get(pid, {}).get("uav_id")
        if uid is None:
            if self._desync_m3m4_anonymous_drop_used:
                return False
            self._desync_m3m4_anonymous_drop_used = True
            return True
        if uid in self._desync_m3m4_drop_uavs:
            return False
        self._desync_m3m4_drop_uavs.add(uid)
        return True

    def _should_suppress_d2z_ack_desync(self, pid: str) -> bool:
        """是否抑制发送 D2Z_ACK（去同步）。"""
        if not self.attack_model.get("intercept_d2z_ack_send"):
            return False
        if not self._desync_first_auth_only():
            return True
        uid = self.uav_db.get(pid, {}).get("uav_id")
        if uid is None:
            if self._desync_ack_anonymous_suppress_used:
                return False
            self._desync_ack_anonymous_suppress_used = True
            return True
        if uid in self._desync_ack_suppress_uavs:
            return False
        self._desync_ack_suppress_uavs.add(uid)
        return True

    def _d2z_ctx(self, pid: Optional[str] = None) -> dict:
        uav_id = None
        if pid and pid in self.uav_db:
            uav_id = self.uav_db[pid].get("uav_id")
        return {
            "flow": "D2Z",
            "peer_zsp_id": self.zsp_id,
            "peer_uav_id": uav_id,
        }

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
        wire_len = len(buf)
        msg_type, pid, payload, mac = PMAPPacket.parse(buf)

        if msg_type == PMAPMessageType.M1:
            self.handle_M1(pid, payload, mac, from_addr, wire_len)

        elif msg_type == PMAPMessageType.M3_4:
            if self._consume_m3m4_drop_desync(pid):
                ctx = self._d2z_ctx(pid)
                self.logger.log_warning(
                    "attack: M3/M4 dropped at ZSP (channel intercept model)",
                    warning_type="attack_intercept_m3_m4",
                    extra={
                        **ctx,
                        "protocol_step": "D2Z_M3_M4_INTERCEPTED",
                        "wire_len": wire_len,
                    },
                )
                return
            self.handle_M3_4(pid, payload, mac, from_addr, wire_len)

        elif msg_type == PMAPMessageType.D2D_M1_2:
            self.handle_D2D_M1_2(pid, payload, mac, from_addr)

        elif msg_type == PMAPMessageType.D2D_M4_5:
            self.handle_D2D_M4_5(pid, payload, mac, from_addr)
        elif msg_type == PMAPMessageType.D2D_M9_10:
            self.handle_D2D_M9_10(pid, payload, mac, from_addr)

    # =========================================================
    # M1
    # =========================================================

    def handle_M1(self, pid, payload, mac, from_addr, wire_len: int):

        ctx = self._d2z_ctx(pid)
        self.logger.log_message_received(
            "M1",
            wire_len,
            extra={**ctx, "protocol_step": "D2Z_M1_RECV"},
        )

        if pid not in self.uav_db:
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=None,
                extra={**ctx, "protocol_step": "D2Z_M1_FAIL_UNKNOWN_PID"},
            )
            return

        crp = self.uav_db[pid]["crp"]
        decrypted = self.chaotic.decrypt_by_crp(payload, crp)
        m1 = PMAP.decode(PMAP.M1, decrypted)
        ni = m1[2]
        if not self.verify_mac(payload, [struct.pack(">d", ni)], mac):
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=self.uav_db[pid].get("uav_id"),
                extra={**ctx, "protocol_step": "D2Z_M1_FAIL_MAC"},
            )
            return

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
        self.logger.log_message_sent(
            "M2",
            len(packet),
            extra={**self._d2z_ctx(pid), "protocol_step": "D2Z_M2_SEND"},
        )

    # =========================================================
    # M3
    # =========================================================

    def handle_M3_4(self, pid, payload, mac, from_addr, wire_len: int):

        ctx = self._d2z_ctx(pid)
        self.logger.log_message_received(
            "M3_M4",
            wire_len,
            extra={**ctx, "protocol_step": "D2Z_M3_M4_RECV"},
        )

        if pid not in self.uav_db:
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=None,
                extra={**ctx, "protocol_step": "D2Z_M3_M4_FAIL_UNKNOWN_PID"},
            )
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
        if not self.verify_mac(payload, [struct.pack(">d", session.ni), struct.pack(">d", response)], mac):
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=self.uav_db[pid].get("uav_id"),
                extra={**ctx, "protocol_step": "D2Z_M3_M4_FAIL_MAC"},
            )
            return

        seed = self.chaotic.encrypt_by_crp(str(session.ni).encode() + str(session.ns).encode(), crp)
        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        challenge, response = canonicalize_crp_pair(challenge, response)
        new_pid = hash_256(str(self.uav_db[pid]["uav_id"]) + str(response))

        if not self.d2z_ack_mode:
            self._d2z_finalize_commit(
                pid, new_pid, challenge, response, session_key, ctx, session, old_crp=crp
            )
            return

        plain_ack = PMAP.encode(PMAP.D2Z_ACK, pid, new_pid, challenge, response)
        enc_ack = self.chaotic.encrypt_by_crp(plain_ack, crp)
        mac_input = enc_ack + struct.pack(">d", ni) + struct.pack(">d", response)
        ack_packet = PMAPPacket.build(
            PMAPMessageType.D2Z_ACK,
            pid,
            enc_ack,
            mac_input,
        )

        if self._should_suppress_d2z_ack_desync(pid):
            self.logger.log_warning(
                "attack: D2Z ACK not sent after M3/M4 (session redundancy test)",
                warning_type="attack_desync",
                extra={**ctx, "protocol_step": "D2Z_ACK_SUPPRESSED"},
            )
            return

        self.SendResponse(ack_packet, session.from_addr)
        self.logger.log_message_sent(
            "D2Z_ACK",
            len(ack_packet),
            extra={**ctx, "protocol_step": "D2Z_ACK_SEND"},
        )
        self._d2z_finalize_commit(
            pid, new_pid, challenge, response, session_key, ctx, session, old_crp=crp
        )

    def _d2z_finalize_commit(
        self,
        old_pid: str,
        new_pid: str,
        challenge: float,
        response: float,
        session_key: int,
        ctx: dict,
        session: D2Z_Session,
        old_crp,
    ) -> None:
        self.UpdateUAVPID(old_pid, new_pid, challenge, response)
        self.D2Z_sessions[new_pid] = self.D2Z_sessions.pop(old_pid)
        key_hash = hex(session_key)[2:]
        self.logger.log_session_established(
            session_id=new_pid,
            session_key_hash=key_hash,
            peer_id=self.uav_db[new_pid].get("uav_id"),
            extra={**self._d2z_ctx(new_pid), "protocol_step": "D2Z_SESSION_KEY"},
        )

        self.logger.log_authentication(
            AuthenticationPhase.SUCCESS,
            success=True,
            peer_id=self.uav_db[new_pid].get("uav_id"),
            extra={**self._d2z_ctx(new_pid), "protocol_step": "D2Z_SUCCESS"},
        )

        self.logger.log_pid_rotation(
            old_pid=old_pid,
            new_pid=new_pid,
            old_crp=old_crp,
            new_crp=self.uav_db[new_pid]["crp"],
        )

    # =========================================================
    # D2D M1_2
    # =========================================================

    def handle_D2D_M1_2(self, pid, payload, mac, from_addr):
        self.logger.log_message_received("D2D M1/2", len(payload))
        
        if pid not in self.uav_db:
            # ⭐ 认证失败
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=None
            )
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
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=None
            )
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
        self.logger.log_message_sent(
            "D2D_M3",
            len(packet),
            extra={"flow": "D2D", "peer_uav_id": self.uav_db[pid].get("uav_id"), "peer_zsp_id": self.zsp_id},
        )
        

    # =========================================================
    # D2D M4
    # =========================================================

    def handle_D2D_M4_5(self, pid, payload, mac, from_addr):

        self.logger.log_message_received("M4/5", len(payload))
        
        if pid not in self.uav_db:
            # ⭐ 认证失败
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=None
            )
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
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=None
            )
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
        self.logger.log_message_sent(
            "D2D_M6_7_8",
            len(packet),
            extra={"flow": "D2D", "peer_uav_id": self.uav_db[pid].get("uav_id"), "peer_zsp_id": self.zsp_id},
        )

        seed = self.chaotic.encrypt_by_crp(
                str(session.n1).encode() + str(session.ni).encode(),
                self.uav_db[pid]["crp"]
        )
        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        challenge, response = canonicalize_crp_pair(challenge, response)
        self.crp = [challenge, response]


    # =========================================================
    # D2D M9
    # =========================================================

    def handle_D2D_M9_10(self, pid, payload, mac, from_addr):

        self.logger.log_message_received("M9/10", len(payload))
        
        if pid not in self.uav_db:
            # ⭐ 认证失败
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=None
            )
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
            # ⭐ 认证失败
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=None
            )
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

