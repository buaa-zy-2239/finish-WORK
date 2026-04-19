import hashlib
import random
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
                "D2Z retry budget exhausted; skip new M1",
                warning_type="d2z_retry_budget_exhausted",
                extra=self._d2z_log_extra("D2Z_RETRY_BUDGET_EXHAUSTED"),
            )
            return
        self._d2z_attempt_counter += 1
        self.rn1 = random.random()
        self.ts1 = random.random() + self.rn1 / 10.0
        auth_u = _hash_bytes(
            bytes.fromhex(self.pseudo_id),
            struct.pack(">d", self.rn1),
            struct.pack(">d", self.ts1),
            bytes.fromhex(self.shared_secret),
        )
        payload = RLBAPlaintext.M1.pack(
            bytes.fromhex(self.pseudo_id),
            float(self.rn1),
            float(self.ts1),
            float(self.zsp_id or 0),
            auth_u,
        )
        mac_input = payload + auth_u + bytes.fromhex(self.shared_secret)
        packet = RLBAPacket.build(RLBAMessageType.M1, self.pid, payload, mac_input)
        self.logger.log_message_sent("M1", len(packet), extra=self._d2z_log_extra("RLBA_INIT"))
        self.SendData(packet)

    def ProcessReceivedData(self, packet_bytes):
        packet_bytes = bytes(packet_bytes)
        if len(packet_bytes) < RLBAPacket.HEADER_STRUCT.size + 32:
            return
        msg_type, pid, payload, mac = RLBAPacket.parse(packet_bytes)
        if pid != self.pid:
            return

        if msg_type == RLBAMessageType.M2:
            (
                pseudo_u_bytes,
                pseudo_d_bytes,
                rn1,
                rn2,
                ts2,
                auth_d,
            ) = RLBAPlaintext.M2.unpack(payload)
            expected_auth = _hash_bytes(
                pseudo_u_bytes,
                pseudo_d_bytes,
                struct.pack(">d", rn1),
                struct.pack(">d", rn2),
                struct.pack(">d", ts2),
                bytes.fromhex(self.shared_secret),
            )
            expected_mac = _hash_hex(payload, expected_auth, bytes.fromhex(self.shared_secret))
            if (
                pseudo_u_bytes.hex() != self.pseudo_id
                or rn1 != self.rn1
                or auth_d != expected_auth
                or mac != expected_mac
            ):
                return
            self.drone_pseudo_id = pseudo_d_bytes.hex()
            self.rn2 = rn2
            self.ts2 = ts2
            self.logger.log_message_received("M2", len(packet_bytes), extra=self._d2z_log_extra("RLBA_CHALLENGE"))
            self.rn3 = random.random()
            self.ts3 = random.random() + self.rn3 / 10.0
            session_key = _hash_bytes(
                struct.pack(">d", self.rn1),
                struct.pack(">d", self.rn2),
                struct.pack(">d", self.rn3),
                pseudo_u_bytes,
                pseudo_d_bytes,
            )
            auth_ud = _hash_bytes(session_key, pseudo_u_bytes, pseudo_d_bytes)
            auth_gss = _hash_bytes(
                pseudo_d_bytes,
                struct.pack(">d", self.rn1),
                struct.pack(">d", self.ts3),
                bytes.fromhex(self.shared_secret),
            )
            m3_payload = RLBAPlaintext.M3.pack(
                pseudo_u_bytes,
                pseudo_d_bytes,
                float(self.rn2),
                float(self.rn3),
                float(self.ts3),
                auth_ud,
                auth_gss,
            )
            m3_mac_input = m3_payload + auth_ud + auth_gss + bytes.fromhex(self.shared_secret)
            packet = RLBAPacket.build(RLBAMessageType.M3, self.pid, m3_payload, m3_mac_input)
            self.logger.log_message_sent("M3", len(packet), extra=self._d2z_log_extra("RLBA_RESPONSE"))
            self.SendData(packet)
            self._rlba_arm_success_deadline()
            return

        if msg_type == RLBAMessageType.SUCCESS:
            if not self._rlba_pending_final:
                return
            pseudo_u_bytes, pseudo_d_bytes, session_key = RLBAPlaintext.SUCCESS.unpack(payload)
            expected_mac = _hash_hex(payload, session_key, bytes.fromhex(self.shared_secret))
            if (
                pseudo_u_bytes.hex() != self.pseudo_id
                or pseudo_d_bytes.hex() != (self.drone_pseudo_id or "")
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
            self.session_key_hash = session_key.hex()
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
