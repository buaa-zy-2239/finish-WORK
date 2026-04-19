import hashlib
import random
import struct

from Common.logging_framework import AuthenticationPhase
from Entity.ZSP.BaseZSP import BaseZSP
from Protocol.StaticBaseline.MsgType import StaticBaselineMessageType
from Protocol.StaticBaseline.Packet import StaticBaselinePacket
from Protocol.StaticBaseline.Plaintext import StaticBaselinePlaintext


class StaticBaselineZSP(BaseZSP):
    def __init__(self, node, zsp_id, blockchain=None, enable_blockchain=True, **_kwargs):
        super().__init__(
            node,
            zsp_id,
            blockchain=blockchain,
            enable_blockchain=enable_blockchain,
            protocol_name="STATIC_BASELINE",
            analysis_family="D2Z",
        )
        self.sessions = {}

    def _d2z_ctx(self, pid=None):
        uav_id = None
        if pid and pid in self.uav_db:
            uav_id = self.uav_db[pid].get("uav_id")
        return {
            "protocol": self.protocol_name,
            "analysis_family": self.analysis_family,
            "flow": "D2Z",
            "peer_zsp_id": self.zsp_id,
            "peer_uav_id": uav_id,
        }

    def _session_key_hash(self, secret_hex, ni, ns):
        return hashlib.sha256(
            bytes.fromhex(secret_hex) + struct.pack(">d", float(ni)) + struct.pack(">d", float(ns))
        ).hexdigest()

    def ProcessRequest(self, buf, from_addr):
        packet_bytes = bytes(buf)
        if len(packet_bytes) < StaticBaselinePacket.HEADER_STRUCT.size + 32:
            return
        msg_type, pid, payload, mac = StaticBaselinePacket.parse(packet_bytes)
        if msg_type == StaticBaselineMessageType.M1:
            self._handle_m1(pid, payload, mac, from_addr, len(packet_bytes))
        elif msg_type == StaticBaselineMessageType.M3:
            self._handle_m3(pid, payload, mac, from_addr, len(packet_bytes))

    def _handle_m1(self, pid, payload, mac, from_addr, wire_len):
        ctx = self._d2z_ctx(pid)
        record = self.uav_db.get(pid)
        if not record:
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=None,
                extra={**ctx, "protocol_step": "STATIC_UNKNOWN_PID", "error_reason": "unknown_pid"},
            )
            return

        pid_bytes, zsp_id, ni = StaticBaselinePlaintext.M1.unpack(payload)
        secret_hex = record.get("secret")
        expected_mac = hashlib.sha256(
            payload + struct.pack(">d", ni) + bytes.fromhex(secret_hex)
        ).hexdigest()
        if pid_bytes.hex() != pid or int(zsp_id) != int(self.zsp_id) or expected_mac != mac:
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=record.get("uav_id"),
                extra={**ctx, "protocol_step": "STATIC_INIT_VERIFY_FAIL", "error_reason": "invalid_m1"},
            )
            return

        self.sessions[pid] = {"ni": ni, "ns": random.random(), "from_addr": from_addr}
        self.logger.log_message_received("M1", wire_len, extra={**ctx, "protocol_step": "STATIC_INIT"})
        ns_val = self.sessions[pid]["ns"]
        m2_payload = StaticBaselinePlaintext.M2.pack(
            bytes.fromhex(pid),
            int(self.zsp_id),
            float(ni),
            float(ns_val),
        )
        m2_mac_input = m2_payload + struct.pack(">d", ni) + struct.pack(">d", ns_val) + bytes.fromhex(secret_hex)
        packet = StaticBaselinePacket.build(StaticBaselineMessageType.M2, pid, m2_payload, m2_mac_input)
        self.logger.log_message_sent("M2", len(packet), extra={**ctx, "protocol_step": "STATIC_CHALLENGE"})
        self.SendResponse(packet, from_addr)

    def _handle_m3(self, pid, payload, mac, _from_addr, wire_len):
        ctx = self._d2z_ctx(pid)
        record = self.uav_db.get(pid)
        session = self.sessions.get(pid)
        if not record or not session:
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=record.get("uav_id") if record else None,
                extra={**ctx, "protocol_step": "STATIC_RESPONSE_ORPHAN", "error_reason": "orphan_m3"},
            )
            return

        pid_bytes, zsp_id, ni, ns, response = StaticBaselinePlaintext.M3.unpack(payload)
        secret_hex = record.get("secret")
        expected_response = bytes.fromhex(self._session_key_hash(secret_hex, ni, ns))
        expected_mac = hashlib.sha256(payload + expected_response + bytes.fromhex(secret_hex)).hexdigest()
        if (
            pid_bytes.hex() != pid
            or int(zsp_id) != int(self.zsp_id)
            or ni != session["ni"]
            or ns != session["ns"]
            or response != expected_response
            or mac != expected_mac
        ):
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=record.get("uav_id"),
                extra={**ctx, "protocol_step": "STATIC_RESPONSE_VERIFY_FAIL", "error_reason": "invalid_m3"},
            )
            return

        self.logger.log_message_received("M3", wire_len, extra={**ctx, "protocol_step": "STATIC_RESPONSE"})
        session_key_hash = self._session_key_hash(secret_hex, ni, ns)
        self.logger.log_authentication(
            AuthenticationPhase.SUCCESS,
            peer_id=record.get("uav_id"),
            extra={**ctx, "protocol_step": "STATIC_SUCCESS", "session_key_hash": session_key_hash},
        )
        self.logger.log_session_established(
            session_id=f"static-{record.get('uav_id')}-{self.zsp_id}",
            session_key_hash=session_key_hash,
            peer_id=record.get("uav_id"),
            extra={**ctx, "protocol_step": "STATIC_SUCCESS"},
        )
        self.sessions.pop(pid, None)
