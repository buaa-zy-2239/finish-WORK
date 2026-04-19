import hashlib
import random
import struct

from Common.logging_framework import AuthenticationPhase
from Entity.UAV.BaseUAV import BaseUAV
from Protocol.StaticBaseline.MsgType import StaticBaselineMessageType
from Protocol.StaticBaseline.Packet import StaticBaselinePacket
from Protocol.StaticBaseline.Plaintext import StaticBaselinePlaintext


def _shared_secret_hex(uav_id: int) -> str:
    return hashlib.sha256(f"STATIC_BASELINE:{uav_id}".encode("utf-8")).hexdigest()


def _static_pid(uav_id: int) -> str:
    return hashlib.sha256(f"STATIC_PID:{uav_id}".encode("utf-8")).hexdigest()


class StaticBaselineUAV(BaseUAV):
    def __init__(self, node, uav_id, auth_trigger_config=None, link_state_config=None, **_kwargs):
        super().__init__(
            node,
            uav_id,
            auth_trigger_config=auth_trigger_config,
            link_state_config=link_state_config,
            protocol_name="STATIC_BASELINE",
            analysis_family="D2Z",
        )
        self.pid = _static_pid(uav_id)
        self.shared_secret = _shared_secret_hex(uav_id)
        self.crp = [self.shared_secret, self.shared_secret]
        self.ni = None
        self.ns = None

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

    def get_registration_record(self):
        return {
            "uav_id": self.id,
            "pid": self.pid,
            "secret": self.shared_secret,
            "protocol": self.protocol_name,
            "analysis_family": self.analysis_family,
        }

    def D2Z_InitiateAuth(self):
        self.ni = random.random()
        payload = StaticBaselinePlaintext.M1.pack(
            StaticBaselinePlaintext.pid_bytes(self.pid),
            int(self.zsp_id or 0),
            float(self.ni),
        )
        mac_input = payload + struct.pack(">d", self.ni) + bytes.fromhex(self.shared_secret)
        packet = StaticBaselinePacket.build(StaticBaselineMessageType.M1, self.pid, payload, mac_input)
        self.logger.log_message_sent("M1", len(packet), extra=self._d2z_log_extra("STATIC_INIT"))
        self.SendData(packet)

    def ProcessReceivedData(self, packet_bytes):
        packet_bytes = bytes(packet_bytes)
        if len(packet_bytes) < StaticBaselinePacket.HEADER_STRUCT.size + 32:
            return
        msg_type, pid, payload, mac = StaticBaselinePacket.parse(packet_bytes)
        if pid != self.pid:
            return

        if msg_type == StaticBaselineMessageType.M2:
            pid_bytes, zsp_id, ni, ns = StaticBaselinePlaintext.M2.unpack(payload)
            if pid_bytes.hex() != self.pid or int(zsp_id) != int(self.zsp_id or 0):
                return
            expected_mac = hashlib.sha256(
                payload + struct.pack(">d", ni) + struct.pack(">d", ns) + bytes.fromhex(self.shared_secret)
            ).hexdigest()
            if expected_mac != mac or ni != self.ni:
                self.logger.log_authentication(
                    AuthenticationPhase.VERIFICATION_FAILED,
                    success=False,
                    peer_id=self.zsp_id,
                    extra=self._d2z_log_extra("STATIC_CHALLENGE_VERIFY_FAIL"),
                )
                return

            self.ns = ns
            self.logger.log_message_received("M2", len(packet_bytes), extra=self._d2z_log_extra("STATIC_CHALLENGE"))
            self.authenticated = True
            response = bytes.fromhex(
                hashlib.sha256(
                    bytes.fromhex(self.shared_secret) + struct.pack(">d", self.ni) + struct.pack(">d", self.ns)
                ).hexdigest()
            )
            m3_payload = StaticBaselinePlaintext.M3.pack(
                StaticBaselinePlaintext.pid_bytes(self.pid),
                int(self.zsp_id or 0),
                float(self.ni),
                float(self.ns),
                response,
            )
            m3_mac_input = m3_payload + response + bytes.fromhex(self.shared_secret)
            packet = StaticBaselinePacket.build(StaticBaselineMessageType.M3, self.pid, m3_payload, m3_mac_input)
            self.logger.log_message_sent("M3", len(packet), extra=self._d2z_log_extra("STATIC_RESPONSE"))
            self.SendData(packet)
            self.logger.log_session_established(
                session_id=self.d2z_auth_session_id,
                session_key_hash=response.hex(),
                peer_id=self.zsp_id,
                extra=self._d2z_log_extra("STATIC_SUCCESS"),
            )
