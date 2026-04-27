import hashlib
import os
import struct
import uuid

from Common.logging_framework import AuthenticationPhase
from Entity.UAV.BaseUAV import BaseUAV
from Protocol.RLBA.MsgType import RLBAMessageType
from Protocol.RLBA.Packet import RLBAPacket
from Protocol.RLBA.Plaintext import RLBAPlaintext


def _hash_bytes(*parts) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        if isinstance(part, str):
            h.update(part.encode("utf-8"))
        else:
            h.update(part)
    return h.digest()


def _hash_hex(*parts) -> str:
    return _hash_bytes(*parts).hex()


def _secure_random() -> float:
    return float(struct.unpack('>d', os.urandom(8))[0]) / (2**64)


def _current_timestamp() -> float:
    import time
    return time.time()


class RLBAUAV(BaseUAV):
    def __init__(
        self,
        node,
        uav_id,
        attack_model=None,
        d2z_ack_mode: bool = False,
        auth_trigger_config=None,
        link_state_config=None,
        **_kwargs,
    ):
        del d2z_ack_mode  # builder passes PMAP_ACK-only flag
        super().__init__(
            node,
            uav_id,
            auth_trigger_config=auth_trigger_config,
            link_state_config=link_state_config,
            protocol_name="RLBA_UAV",
            analysis_family="D2Z",
        )
        self.attack_model = attack_model if attack_model is not None else {}
        self.pid = _hash_hex(f"RLBA_PID:{uav_id}")
        self.shared_secret = _hash_hex(f"RLBA_SECRET:{uav_id}")
        self.pseudo_id = _hash_hex(f"RLBA_PSEUDO:{uav_id}")
        self.drone_pseudo_id = None
        self.rn1 = None
        self.rn2 = None
        self.rn3 = None
        self.ts1 = None
        self.ts2 = None
        self.ts3 = None
        self.session_key_hash = None
        self._rlba_pending_final = False
        self._rlba_success_deadline_gen = 0
        self._d2z_attempt_counter = 0
        self._d2z_attempt_session_id = None
        # PUF相关
        self.puf_challenge = None
        self.puf_response = None

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
        if self._rlba_pending_final:
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

    def _rlba_arm_success_deadline(self):
        """M3 发出后等待 ZSP 的 SUCCESS（与 PMAP_ACK 等待 D2Z_ACK 同叙事）。"""
        self._rlba_pending_final = True
        t = float(self.attack_model.get("d2z_ack_timeout_s", 5.0))
        self._rlba_success_deadline_gen += 1
        g = self._rlba_success_deadline_gen
        self._safe_schedule(t, self._rlba_success_deadline, g)

    def _generate_puf_response(self, challenge: float) -> float:
        """生成PUF响应"""
        # 这里使用哈希函数模拟PUF行为，实际应用中应该使用真实的PUF实现
        response = _hash_hex(f"PUF:{self.id}:{challenge}")
        return float(struct.unpack('>d', bytes.fromhex(response[:16]))[0])

    def on_connected_to_zsp(self):
        """连接到ZSP时的回调方法，RLBA协议中认证由ZSP初始化，所以不自动触发认证"""
        # RLBA协议中，认证由ZSP初始化，所以这里不自动触发认证
        pass

    def _rlba_success_deadline(self, gen: int):
        if gen != self._rlba_success_deadline_gen:
            return
        if not self._rlba_pending_final:
            return
        self._rlba_pending_final = False
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
        self._safe_schedule(0.5, self.D2Z_InitiateAuth)

    def get_registration_record(self):
        return {
            "uav_id": self.id,
            "pid": self.pid,
            "pseudo_id": self.pseudo_id,
            "secret": self.shared_secret,
            "protocol": self.protocol_name,
            "analysis_family": self.analysis_family,
        }

    def D2Z_InitiateAuth(self):
        self._refresh_attempt_scope()
        max_attempts = self._max_d2z_attempts()
        if max_attempts is not None and self._d2z_attempt_counter >= max_attempts:
            self.logger.log_warning(
                "D2Z retry budget exhausted; skip new auth",
                warning_type="d2z_retry_budget_exhausted",
                extra=self._d2z_log_extra("D2Z_RETRY_BUDGET_EXHAUSTED"),
            )
            return
        # RLBA协议中，认证由ZSP初始化，所以这里不发送M1消息
        # 只记录认证初始化事件
        self.logger.log_authentication(
            AuthenticationPhase.INITIATED,
            peer_id=self.zsp_id,
            extra={
                "protocol": self.protocol_name,
                "analysis_family": self.analysis_family,
                "auth_session_id": self.d2z_auth_session_id,
                "flow": "D2Z",
                "protocol_step": "RLBA_INIT",
                "peer_zsp_id": self.zsp_id,
                "peer_uav_id": self.id,
            },
        )

    def ProcessReceivedData(self, packet_bytes):
        packet_bytes = bytes(packet_bytes)
        if len(packet_bytes) < RLBAPacket.HEADER_STRUCT.size + 32:
            return
        msg_type, pid, payload, mac = RLBAPacket.parse(packet_bytes)
        if pid != self.pid:
            return

        if msg_type == RLBAMessageType.GSS_TO_UAV:
            # 处理来自GSS的认证请求
            gss_id_bytes, user_id_bytes, rn1, rn2, ts2, auth_g = RLBAPlaintext.GSS_TO_UAV.unpack(payload)
            # 生成PUF挑战和响应
            puf_challenge = _secure_random()
            puf_response = self._generate_puf_response(puf_challenge)
            expected_auth = _hash_bytes(
                gss_id_bytes,
                user_id_bytes,
                struct.pack(">d", rn1),
                struct.pack(">d", rn2),
                struct.pack(">d", ts2),
                struct.pack(">d", puf_challenge),
                struct.pack(">d", puf_response),
                bytes.fromhex(self.shared_secret),
            )
            expected_mac = _hash_hex(payload, expected_auth, bytes.fromhex(self.shared_secret))
            if auth_g != expected_auth or mac != expected_mac:
                return
            
            self.logger.log_message_received("GSS_TO_UAV", len(packet_bytes), extra=self._d2z_log_extra("RLBA_GSS_CHALLENGE"))
            
            # 生成安全随机数
            rn3 = _secure_random()
            # 使用真实时间戳
            ts3 = _current_timestamp()
            
            # 计算会话密钥
            session_key_ud = _hash_bytes(
                struct.pack(">d", rn1),
                struct.pack(">d", rn2),
                struct.pack(">d", rn3),
                user_id_bytes,
                gss_id_bytes,
                struct.pack(">d", puf_challenge),
                struct.pack(">d", puf_response),
            )
            
            # 计算认证值
            auth_d = _hash_bytes(session_key_ud, user_id_bytes, gss_id_bytes)
            auth_gss = _hash_bytes(
                gss_id_bytes,
                struct.pack(">d", rn1),
                struct.pack(">d", ts3),
                bytes.fromhex(self.shared_secret),
            )
            
            # 构建UAV到GSS的响应消息
            uav_to_gss_payload = RLBAPlaintext.UAV_TO_GSS.pack(
                bytes.fromhex(self.pseudo_id),
                gss_id_bytes,
                user_id_bytes,
                float(rn2),
                float(rn3),
                float(ts3),
                auth_d,
                auth_gss,
            )
            uav_to_gss_mac_input = uav_to_gss_payload + auth_d + auth_gss + bytes.fromhex(self.shared_secret)
            packet = RLBAPacket.build(RLBAMessageType.UAV_TO_GSS, self.pid, uav_to_gss_payload, uav_to_gss_mac_input)
            self.logger.log_message_sent("UAV_TO_GSS", len(packet), extra=self._d2z_log_extra("RLBA_UAV_RESPONSE"))
            self.SendData(packet)
            self._rlba_arm_success_deadline()
            return

        if msg_type == RLBAMessageType.SUCCESS:
            if not self._rlba_pending_final:
                return
            # 处理来自GSS的成功消息
            gss_id_bytes, user_id_bytes, uav_id_bytes, session_key_ug, session_key_ud = RLBAPlaintext.SUCCESS.unpack(payload)
            expected_mac = _hash_hex(payload, session_key_ug, session_key_ud, bytes.fromhex(self.shared_secret))
            if (
                uav_id_bytes.hex() != self.pseudo_id
                or mac != expected_mac
            ):
                return
            self._rlba_success_deadline_gen += 1
            self._rlba_pending_final = False
            self.logger.log_message_received(
                "RLBA_SUCCESS",
                len(packet_bytes),
                extra={**self._d2z_log_extra("D2Z_ACK_RECV")},
            )
            self.authenticated = True
            self.session_key_hash = session_key_ud.hex()
            # 更新PID
            new_pid = _hash_hex(f"RLBA_PID:{self.id}")
            self.pid = new_pid
            self.logger.log_session_established(
                session_id=self.d2z_auth_session_id,
                session_key_hash=self.session_key_hash,
                peer_id=self.zsp_id,
                extra=self._d2z_log_extra("RLBA_SUCCESS"),
            )
            self.logger.log_authentication(
                AuthenticationPhase.SUCCESS,
                success=True,
                peer_id=self.zsp_id,
                extra=self._d2z_log_extra("D2Z_SUCCESS"),
            )
