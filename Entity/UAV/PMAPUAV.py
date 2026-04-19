from Entity.UAV.BaseUAV import BaseUAV
from Common.logging_framework import AuthenticationPhase, IdentifierOperation
from Common.crp_chain_codec import canonicalize_scalar
from Caculator.ChaoticMap import ChaoticMap
from KeyGen.PUFGenerator import PUFGenerator
from Caculator.Hash import hash_256

from Protocol.PMAP.PMAPPlaintext import PMAPPlaintext
from Protocol.PMAP.Packet import PMAPPacket
from Protocol.PMAP.MsgType import PMAPMessageType

import hashlib
import random
import struct
import uuid


def _d2z_mac_hex(payload_bytes: bytes, params) -> str:
    mac_input = payload_bytes
    for p in params:
        mac_input += p
    return hashlib.sha256(mac_input).hexdigest()


class D2D_Session:

    def __init__(self):
        self.ni = None
        self.nj = None
        self.n2 = None
        self.session_key = None


class PMAP_UAV(BaseUAV):

    def __init__(
        self,
        node,
        uav_id,
        attack_model=None,
        d2z_ack_mode: bool = False,
        auth_trigger_config=None,
        link_state_config=None,
    ):

        super().__init__(
            node,
            uav_id,
            auth_trigger_config=auth_trigger_config,
            link_state_config=link_state_config,
            protocol_name="PMAP_ACK" if d2z_ack_mode else "PMAP",
            analysis_family="D2Z",
        )

        self.attack_model = attack_model if attack_model is not None else {}
        self.d2z_ack_mode = bool(d2z_ack_mode)
        self._d2z_pending_commit = None
        self._d2z_ack_deadline_gen = 0
        self._d2z_attempt_counter = 0
        self._d2z_attempt_session_id = None

        self.chaotic = ChaoticMap()
        self.puf = PUFGenerator(uav_id)

        self.zsp_id = None

        # CRP
        self.crp = [None, None]
        self.new_crp = [None, None]
        self.crp[0] = 0.1 + uav_id * 0.01
        self.crp[1] = self.puf.generate_response(self.crp[0])
        self.pid = hash_256(str(self.id) + str(self.crp[1]))

        # D2Z
        self.ni = None
        self.ns = None

        self.session_key = None

        # D2D sessions
        self.D2D_sessions = {}

    def _d2z_log_extra(self, protocol_step: str) -> dict:
        return {
            "protocol": self.protocol_name,
            "analysis_family": self.analysis_family,
            "auth_session_id": getattr(self, "d2z_auth_session_id", None),
            "flow": "D2Z",
            "protocol_step": protocol_step,
            "peer_zsp_id": self.zsp_id,
            "peer_uav_id": self.id,
        }

    def _can_trigger_d2z_auth(self) -> bool:
        if not super()._can_trigger_d2z_auth():
            return False
        # PMAP_ACK 在收到 ACK 或 ACK 超时重试前，禁止新的动态触发重入。
        if self.d2z_ack_mode and self._d2z_pending_commit is not None:
            return False
        return True

    def _max_d2z_attempts(self):
        v = self.attack_model.get("max_d2z_attempts")
        if v is None:
            return None
        try:
            n = int(v)
            return n if n >= 1 else None
        except Exception:
            return None

    def _refresh_attempt_scope(self):
        sid = getattr(self, "d2z_auth_session_id", None)
        if sid != self._d2z_attempt_session_id:
            self._d2z_attempt_session_id = sid
            self._d2z_attempt_counter = 0

    # =========================================================
    # Initialization
    # =========================================================

    def StartApplication(self):

        

        super().StartApplication()


    # =========================================================
    # D2Z Initiate (M1)
    # =========================================================

    def D2Z_InitiateAuth(self):
        self._refresh_attempt_scope()
        max_attempts = self._max_d2z_attempts()
        if max_attempts is not None and self._d2z_attempt_counter >= max_attempts:
            self.logger.log_warning(
                "D2Z retry budget exhausted; skip new M1",
                warning_type="d2z_retry_budget_exhausted",
                extra=self._d2z_log_extra("D2Z_RETRY_BUDGET_EXHAUSTED"),
            )
            return
        self._d2z_attempt_counter += 1

        self.ni = random.random()
        plaintext = PMAPPlaintext.encode(
            PMAPPlaintext.M1,
            self.pid,
            self.zsp_id,
            self.ni
        )
        
        encrypted = self.chaotic.encrypt_by_crp(
            plaintext,
            self.crp
        )
        mac_input = encrypted + struct.pack(">d", self.ni)
        packet = PMAPPacket.build(
            PMAPMessageType.M1,
            self.pid,
            encrypted,
            mac_input
        )
        
        ex = self._d2z_log_extra("D2Z_M1_SEND")
        self.logger.log_message_sent("M1", len(packet), extra=ex)

        self.SendData(packet)


    # =========================================================
    # D2D Initiate (M1 M2)
    # =========================================================

    def D2D_InitiateAuth(self, target_pid):

        session = D2D_Session()

        session.ni = random.random()

        self.D2D_sessions[target_pid] = session

        m1_plain = PMAPPlaintext.encode(
            PMAPPlaintext.D2D_M1,
            self.pid,
            self.zsp_id,
            session.ni
        )

        m2_plain = PMAPPlaintext.encode(
            PMAPPlaintext.D2D_M2,
            self.pid,
            self.zsp_id,
            session.ni,
            target_pid
        )

        enc1 = self.chaotic.encrypt_by_crp(m1_plain, self.crp)
        enc2 = self.chaotic.encrypt_by_crp(m2_plain, self.crp)

        payload = enc1 + enc2

        mac_input = payload + struct.pack(">d", session.ni) + bytes.fromhex(target_pid)

        packet = PMAPPacket.build(
            PMAPMessageType.D2D_M1_2,
            self.pid,
            payload,
            mac_input
        )

        self.logger.log_message_sent("D2D M1/2", len(packet))
        self.logger.log_authentication(AuthenticationPhase.MESSAGE_SENT)

        self.SendData(packet)



    # =========================================================
    # Receive
    # =========================================================

    def ProcessReceivedData(self, packet_bytes):
        packet_bytes = bytes(packet_bytes)
        ack_wire = PMAPPacket.d2z_ack_wire_len()
        # NS-3 / CSMA 等可能把连续多帧放进一次 Recv；首帧为 D2Z_ACK 时只消费固定线长，余量递归处理。
        if (
            self.d2z_ack_mode
            and len(packet_bytes) > ack_wire
            and packet_bytes[0] == PMAPMessageType.D2Z_ACK
        ):
            self._handle_d2z_ack(packet_bytes[:ack_wire])
            tail = packet_bytes[ack_wire:]
            if tail:
                self.ProcessReceivedData(tail)
            return
        try:
            if len(packet_bytes) < PMAPPacket.HEADER_STRUCT.size + 32:
                return
            msg_type, pid, payload, mac = PMAPPacket.parse(packet_bytes)

            # D2Z_ACK：广播场景下报文头 PID 可能是他机旧身份；在丢弃「foreign PID」之前
            # 先处理，并由 ACK 明文内的 old/new PID 与 pending 校验绑定。
            if msg_type == PMAPMessageType.D2Z_ACK and self.d2z_ack_mode:
                self._handle_d2z_ack(packet_bytes)
                return

            if pid != self.pid:
                self.logger.log_error(
                    "Received packet for foreign PID",
                    error_type="invalid_pid",
                    extra=self._d2z_log_extra("D2Z_PID_MISMATCH"),
                )
                return

            # -----------------------------------------------------
            # Receive M2
            # -----------------------------------------------------

            if msg_type == PMAPMessageType.M2:
                self._d2z_pending_commit = None
                self._d2z_ack_deadline_gen += 1

                self.logger.log_message_received(
                    "M2",
                    len(packet_bytes),
                    extra=self._d2z_log_extra("D2Z_M2_RECV"),
                )

                plaintext = self.chaotic.decrypt_by_crp(
                    payload,
                    self.crp
                )

                pid, zsp, ni, ns = PMAPPlaintext.decode(
                    PMAPPlaintext.M2,
                    plaintext
                )
                if ni != self.ni:

                    self.logger.log_error(
                        "D2Z M2 nonce mismatch",
                        error_type="d2z_m2_nonce",
                        extra=self._d2z_log_extra("D2Z_M2_NONCE_FAIL"),
                    )
                    return

                self.ns = ns

                self._send_M3_M4()

            # -----------------------------------------------------
            # Receive D2D M3
            # -----------------------------------------------------

            elif msg_type == PMAPMessageType.D2D_M3:

                plain = self.chaotic.decrypt_by_crp(payload, self.crp)

                pid_i, zsp, pid_j, ni, n1 = PMAPPlaintext.decode(
                    PMAPPlaintext.D2D_M3,
                    plain
                )
                session = self.D2D_sessions[pid_j]
                if ni != session.ni:
                    self.logger.log_error(
                        "D2D M3 nonce mismatch",
                        error_type="d2d_m3_nonce",
                    )
                    return

                session.n1 = n1

                session.ni = random.random()

                m4_plain = PMAPPlaintext.encode(
                    PMAPPlaintext.D2D_M4,
                    self.pid,
                    self.zsp_id,
                    pid_j,
                    n1,
                    session.ni
                )

                seed = self.chaotic.encrypt_by_crp(
                    str(session.n1).encode() + str(session.ni).encode(),
                    self.crp
                )

                challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
                challenge = canonicalize_scalar(challenge)
                response = self.puf.generate_response(challenge)
                response = canonicalize_scalar(response)

                self.new_crp = [challenge, response]

                m5_plain = PMAPPlaintext.encode(
                    PMAPPlaintext.D2D_M5,
                    self.pid,
                    self.zsp_id,
                    pid_j,
                    n1,
                    session.ni,
                    response
                )

                enc4 = self.chaotic.encrypt_by_crp(m4_plain, self.crp)
                enc5 = self.chaotic.encrypt_by_crp(m5_plain, self.crp)
                mac_input = enc4 + enc5 + struct.pack(">d", session.ni) +struct.pack(">d", response)
                packet = PMAPPacket.build(
                    PMAPMessageType.D2D_M4_5,
                    self.pid,
                    enc4 + enc5,
                    mac_input
                )

                self.SendData(packet)


            # -----------------------------------------------------
            # Receive D2D M6 M7 M8
            # -----------------------------------------------------

            elif msg_type == PMAPMessageType.D2D_M6_7_8:
                
                size6 = PMAPPlaintext.D2D_M6.size
                size7 = PMAPPlaintext.D2D_M7.size

                enc6 = payload[:size6]
                enc7 = payload[size6:size6 + size7]
                enc8 = payload[size6 + size7:]
                
                m6 = self.chaotic.decrypt_by_crp(enc6, self.crp)
                m7 = self.chaotic.decrypt_by_crp(enc7, self.crp)
                m8 = self.chaotic.decrypt_by_crp(enc8, self.crp)
                
                _, zsp, n2 = PMAPPlaintext.decode(PMAPPlaintext.D2D_M6, m6)
                
                _, _, _, ni = PMAPPlaintext.decode(
                    PMAPPlaintext.D2D_M7,
                    m7
                )
                _,_,_,_,pid_i = PMAPPlaintext.decode(
                    PMAPPlaintext.D2D_M8,
                    m8
                )
                session = D2D_Session()
                session.n2 = n2
                session.ni = ni
                session.nj = random.random()
                self.D2D_sessions[pid_i] = session

                seed = self.chaotic.encrypt_by_crp(
                    str(n2).encode() + str(session.nj).encode(),
                    self.crp
                )

                challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
                challenge = canonicalize_scalar(challenge)
                response = self.puf.generate_response(challenge)
                response = canonicalize_scalar(response)

                m9_plain = PMAPPlaintext.encode(
                    PMAPPlaintext.D2D_M9,
                    self.pid,
                    self.zsp_id,
                    pid_i,
                    n2,
                    session.nj
                )

                m10_plain = PMAPPlaintext.encode(
                    PMAPPlaintext.D2D_M10,
                    self.pid,
                    self.zsp_id,
                    pid_i,
                    n2,
                    session.nj,
                    response
                )

                enc9 = self.chaotic.encrypt_by_crp(m9_plain, self.crp)
                enc10 = self.chaotic.encrypt_by_crp(m10_plain, self.crp)
                mac_input = enc9 + enc10 + struct.pack(">d", session.nj) + struct.pack(">d", response)
                packet = PMAPPacket.build(
                    PMAPMessageType.D2D_M9_10,
                    self.pid,
                    enc9 + enc10,
                    mac_input
                )

                self.SendData(packet)
                self.crp = [challenge, response]
                _old_pid = self.pid
                self.pid = hash_256(str(self.id) + str(response))
                self._desync_notify_local_pid(_old_pid, self.pid, "d2d_pid_roll")
                session.session_key = \
                int(hash_256(str(session.ni)), 16) ^ \
                int(hash_256(str(session.nj)), 16)

                key_hash = hashlib.sha256(str(session.session_key).encode()).hexdigest()[:16]
                self.logger.log_session_established(
                    session_key_hash=key_hash,
                    peer_id=self.zsp_id,
                    extra={"flow": "D2D", "protocol_step": "D2D_SESSION_KEY", "peer_uav_id": self.id},
                )

                self.logger.log_authentication(
                    AuthenticationPhase.SUCCESS,
                    success=True,
                    peer_id=self.zsp_id,
                    extra={"flow": "D2D", "protocol_step": "D2D_SUCCESS"},
                )
                    


            # -----------------------------------------------------
            # Receive D2D M11
            # -----------------------------------------------------
            elif msg_type == PMAPMessageType.D2D_M11:

                plaintext = self.chaotic.decrypt_by_crp(
                    payload,
                    self.crp
                )

                pid_j, zsp, pid_i, ni, nj = PMAPPlaintext.decode(
                    PMAPPlaintext.D2D_M11,
                    plaintext
                )

                session = self.D2D_sessions.get(pid_i)

                if session is None:
                    return

                session.nj = nj

                session.session_key = \
                    int(hash_256(str(ni)), 16) ^ \
                    int(hash_256(str(nj)), 16)

                key_hash = hashlib.sha256(bytes.fromhex(hex(session.session_key))).hexdigest()[:16]
                self.logger.log_session_established(
                    session_key_hash=key_hash,
                    peer_id=pid_j,
                )
                
                # ⭐ 记录认证成功
                self.logger.log_authentication(
                    AuthenticationPhase.SUCCESS,
                    success=True,
                    peer_id=pid_j
                )
                new_pid = hash_256(str(self.id)+str(self.new_crp[1]))
                _old_pid = self.pid
                self.pid = new_pid
                self._desync_notify_local_pid(_old_pid, self.pid, "d2d_m11_pid")
                self.crp = self.new_crp
        except Exception as e:
            self.logger.log_message_error(
                "UNKNOWN",
                str(e),
                len(packet_bytes),
                extra=self._d2z_log_extra("D2Z_PROCESS_ERROR"),
            )



    # =========================================================
    # Send M3 M4
    # =========================================================

    def _d2z_ack_deadline(self, gen: int):
        if gen != self._d2z_ack_deadline_gen:
            return
        if self._d2z_pending_commit is None:
            return
        self._d2z_pending_commit = None
        max_attempts = self._max_d2z_attempts()
        if max_attempts is not None and self._d2z_attempt_counter >= max_attempts:
            self.logger.log_warning(
                "D2Z ACK timeout and retry budget exhausted",
                warning_type="d2z_retry_budget_exhausted",
                extra=self._d2z_log_extra("D2Z_RETRY_BUDGET_EXHAUSTED"),
            )
            self.logger.log_authentication(
                AuthenticationPhase.TIMEOUT,
                success=False,
                peer_id=self.zsp_id,
                extra=self._d2z_log_extra("D2Z_TIMEOUT"),
            )
            return
        # 记录ACK超时事件，标记当前会话为超时
        self.logger.log_authentication(
            AuthenticationPhase.TIMEOUT,
            success=False,
            peer_id=self.zsp_id,
            extra={
                **self._d2z_log_extra("D2Z_ACK_TIMEOUT"),
                "auth_session_id": self.d2z_auth_session_id,
            },
        )
        self.logger.log_warning(
            "D2Z ACK timeout — UAV keeps old PID/CRP and retries M1 (session redundancy)",
            warning_type="d2z_ack_timeout",
            extra=self._d2z_log_extra("D2Z_ACK_TIMEOUT"),
        )
        self.authenticated = False
        self.d2z_auth_session_id = str(uuid.uuid4())
        self.logger.log_authentication(
            AuthenticationPhase.INITIATED,
            peer_id=self.zsp_id,
            extra={
                "protocol": self.protocol_name,
                "analysis_family": self.analysis_family,
                "auth_session_id": self.d2z_auth_session_id,
                "flow": "D2Z",
                "protocol_step": "D2Z_RETRY_AFTER_ACK_TIMEOUT",
                "peer_zsp_id": self.zsp_id,
                "peer_uav_id": self.id,
            },
        )
        # ACK超时后立即重试M1（不等待），提高响应速度和成功率
        self.D2Z_InitiateAuth()

    def _handle_d2z_ack(self, packet_bytes: bytes):
        if not self._d2z_pending_commit:
            return
        packet_bytes = bytes(packet_bytes)
        ack_wire = PMAPPacket.d2z_ack_wire_len()
        if (
            len(packet_bytes) > ack_wire
            and packet_bytes
            and packet_bytes[0] == PMAPMessageType.D2Z_ACK
        ):
            packet_bytes = packet_bytes[:ack_wire]
        try:
            msg_type, hdr_pid, payload, mac_hex = PMAPPacket.parse(packet_bytes)
        except Exception:
            return
        if msg_type != PMAPMessageType.D2Z_ACK:
            return
        ack_plain_size = PMAPPlaintext.D2Z_ACK.size
        hdr_for_self = hdr_pid == self.pid
        if len(payload) != ack_plain_size:
            if hdr_for_self:
                self.logger.log_error(
                    "D2Z ACK ciphertext length invalid",
                    error_type="d2z_ack_len",
                    extra={
                        **self._d2z_log_extra("D2Z_ACK_LEN_FAIL"),
                        "payload_cipher_len": len(payload),
                        "expected_cipher_len": ack_plain_size,
                    },
                )
            return
        pend = self._d2z_pending_commit
        if _d2z_mac_hex(payload, [struct.pack(">d", pend["ni"]), struct.pack(">d", pend["response"])]) != mac_hex:
            if hdr_for_self:
                self.logger.log_error(
                    "D2Z ACK MAC verification failed",
                    error_type="d2z_ack_mac",
                    extra=self._d2z_log_extra("D2Z_ACK_MAC_FAIL"),
                )
            return
        plain = self.chaotic.decrypt_by_crp(payload, self.crp)
        if len(plain) != ack_plain_size:
            self.logger.log_error(
                "D2Z ACK plaintext length invalid after decrypt",
                error_type="d2z_ack_plain_len",
                extra={
                    **self._d2z_log_extra("D2Z_ACK_PLAIN_LEN_FAIL"),
                    "plain_len": len(plain),
                    "expected_plain_len": ack_plain_size,
                },
            )
            return
        try:
            old_b, new_b, ch, resp = PMAPPlaintext.decode(PMAPPlaintext.D2Z_ACK, plain)
        except struct.error as e:
            self.logger.log_error(
                f"D2Z ACK plaintext decode failed: {e}",
                error_type="d2z_ack_decode",
                extra=self._d2z_log_extra("D2Z_ACK_DECODE_FAIL"),
            )
            return
        old_pid_wire = PMAPPlaintext.bytes_to_pid(old_b)
        new_pid_wire = PMAPPlaintext.bytes_to_pid(new_b)
        if old_pid_wire != self.pid:
            # 常见于广播下收到他机 ACK；静默忽略即可。
            return
        if hdr_pid != self.pid and hdr_pid != pend["new_pid"]:
            self.logger.log_warning(
                "D2Z ACK header PID does not match self or pending new PID",
                warning_type="d2z_ack_hdr_pid",
                extra={
                    **self._d2z_log_extra("D2Z_ACK_HDR_PID_WARN"),
                    "header_pid": hdr_pid,
                    "plaintext_old_pid": old_pid_wire,
                    "pending_new_pid": pend["new_pid"],
                },
            )
        if new_pid_wire != pend["new_pid"]:
            self.logger.log_error(
                "D2Z ACK new PID mismatch",
                error_type="d2z_ack_pid",
                extra=self._d2z_log_extra("D2Z_ACK_PID_MISMATCH"),
            )
            return
        if abs(float(ch) - float(pend["new_crp"][0])) > 1e-9 or abs(float(resp) - float(pend["new_crp"][1])) > 1e-9:
            self.logger.log_error(
                "D2Z ACK CRP mismatch",
                error_type="d2z_ack_crp",
                extra=self._d2z_log_extra("D2Z_ACK_CRP_MISMATCH"),
            )
            return

        self._d2z_ack_deadline_gen += 1
        self._d2z_pending_commit = None

        self.logger.log_message_received(
            "D2Z_ACK",
            len(packet_bytes),
            extra=self._d2z_log_extra("D2Z_ACK_RECV"),
        )

        _old_pid = self.pid
        self.pid = pend["new_pid"]
        self._desync_notify_local_pid(_old_pid, self.pid, "pmap_ack_apply")
        self.crp = pend["new_crp"]
        self.session_key = pend["session_key"]

        key_hash = hex(self.session_key)[2:]
        self.logger.log_session_established(
            session_key_hash=key_hash,
            peer_id=self.zsp_id,
            extra=self._d2z_log_extra("D2Z_SESSION_KEY"),
        )
        self.logger.log_authentication(
            AuthenticationPhase.SUCCESS,
            success=True,
            peer_id=self.zsp_id,
            extra=self._d2z_log_extra("D2Z_SUCCESS"),
        )
        self.authenticated = True

    def _send_M3_M4(self):
        try:
            self.ni = random.random()
            seed = self.chaotic.encrypt_by_crp(
                str(self.ni).encode() + str(self.ns).encode(),
                self.crp
            )
            challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
            challenge = canonicalize_scalar(challenge)
            response = self.puf.generate_response(challenge)
            response = canonicalize_scalar(response)
            m3_plain = PMAPPlaintext.encode(
                PMAPPlaintext.M3,
                self.pid,
                self.zsp_id,
                self.ns,
                self.ni
            )

            m4_plain = PMAPPlaintext.encode(
                PMAPPlaintext.M4,
                self.pid,
                self.zsp_id,
                self.ns,
                self.ni,
                response
            )
            enc3 = self.chaotic.encrypt_by_crp(m3_plain, self.crp)
            enc4 = self.chaotic.encrypt_by_crp(m4_plain, self.crp)

            mac_input = enc3 + enc4 + struct.pack(">d", self.ni) + struct.pack(">d", response)
            packet = PMAPPacket.build(
                PMAPMessageType.M3_4,
                self.pid,
                enc3+enc4,
                mac_input
            )
            self.SendData(packet)

            self.logger.log_message_sent(
                "M3_M4",
                len(packet),
                extra=self._d2z_log_extra("D2Z_M3_M4_SEND"),
            )

            new_pid = hash_256(str(self.id) + str(response))
            session_key = int(hash_256(str(self.ni)), 16) ^ int(hash_256(str(self.ns)), 16)

            if self.d2z_ack_mode:
                self._d2z_pending_commit = {
                    "new_pid": new_pid,
                    "new_crp": [challenge, response],
                    "session_key": session_key,
                    "ni": self.ni,
                    "response": response,
                }
                key_hash = hex(session_key)[2:]
                self.logger.log_session_established(
                    session_key_hash=key_hash,
                    peer_id=self.zsp_id,
                    extra=self._d2z_log_extra("D2Z_SESSION_KEY_PENDING_ACK"),
                )
                t = float(self.attack_model.get("d2z_ack_timeout_s", 5.0))
                self._d2z_ack_deadline_gen += 1
                g = self._d2z_ack_deadline_gen
                self._safe_schedule(t, self._d2z_ack_deadline, g)
                return

            self.crp = [challenge, response]
            _old_pid = self.pid
            self.pid = new_pid
            self._desync_notify_local_pid(_old_pid, self.pid, "pmap_post_m3m4_local")
            self.session_key = session_key

            key_hash = hex(self.session_key)[2:]
            self.logger.log_session_established(
                session_key_hash=key_hash,
                peer_id=self.zsp_id,
                extra=self._d2z_log_extra("D2Z_SESSION_KEY"),
            )

            self.logger.log_authentication(
                AuthenticationPhase.SUCCESS,
                success=True,
                peer_id=self.zsp_id,
                extra=self._d2z_log_extra("D2Z_SUCCESS"),
            )
            self.authenticated = True

            delay = self.attack_model.get("retry_d2z_after_intercept_s")
            if self.attack_model.get("intercept_m3_m4_delivery") and delay is not None:
                if self.attack_model.get("desync_attack_first_auth_only", False):
                    if not getattr(self, "_desync_intercept_retry_scheduled", False):
                        self._desync_intercept_retry_scheduled = True
                        self._safe_schedule(
                            float(delay), self._attack_simulate_d2z_timeout_retry
                        )
                else:
                    self._safe_schedule(float(delay), self._attack_simulate_d2z_timeout_retry)

        except Exception as e:
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=self.zsp_id,
                extra={**self._d2z_log_extra("D2Z_FAILED"), "error_reason": str(e)},
            )
            self.logger.log_error(str(e), error_type="M4_processing")

    def _attack_simulate_d2z_timeout_retry(self):
        """Simulate max-auth-time expiry: UAV retries D2Z while ZSP never applied M3/M4."""
        if self.d2z_ack_mode:
            return
        if not self.attack_model.get("intercept_m3_m4_delivery"):
            return
        self.authenticated = False
        self.d2z_auth_session_id = str(uuid.uuid4())
        self.logger.log_warning(
            "attack: simulated D2Z timeout then retry (UAV PID/CRP already rotated; ZSP DB stale)",
            warning_type="attack_d2z_timeout_retry",
            extra={
                **self._d2z_log_extra("D2Z_ATTACK_TIMEOUT_RESET"),
                "auth_session_id": self.d2z_auth_session_id,
            },
        )
        self.logger.log_authentication(
            AuthenticationPhase.INITIATED,
            peer_id=self.zsp_id,
            extra={
                "auth_session_id": self.d2z_auth_session_id,
                "flow": "D2Z",
                "protocol_step": "D2Z_ATTACK_RETRY_AFTER_INTERCEPT",
                "peer_zsp_id": self.zsp_id,
                "peer_uav_id": self.id,
            },
        )
        # M3/M4被拦截后立即重试（不等待），提高攻击场景下的恢复速度
        self.D2Z_InitiateAuth()
