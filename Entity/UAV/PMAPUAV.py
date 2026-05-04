"""
PMAP协议UAV实现
"""

from Entity.UAV.BaseUAV import BaseUAV
from Entity.common.session_tracker_mixin import UAVSessionTrackerMixin
from Common.logging_framework import AuthenticationPhase, IdentifierOperation
from Common.crp_chain_codec import canonicalize_scalar
from Caculator.ChaoticMap import ChaoticMap
from KeyGen.PUFGenerator import PUFGenerator
from Caculator.Hash import hash_256
from Simulator.session_tracker import SessionTracker

from Protocol.PMAP.PMAPPlaintext import PMAPPlaintext
from Protocol.PMAP.Packet import PMAPPacket
from Protocol.PMAP.MsgType import PMAPMessageType
from Protocol.PMAP.pmap_common import d2z_mac_hex, D2D_Session

import hashlib
import random
import struct
import uuid


class PMAP_UAV(BaseUAV, UAVSessionTrackerMixin):

    def __init__(
        self,
        node,
        uav_id,
        attack_model=None,
        d2z_ack_mode: bool = False,
        auth_trigger_config=None,
        link_state_config=None,
        session_tracker=None,
    ):

        super().__init__(
            node,
            uav_id,
            auth_trigger_config=auth_trigger_config,
            link_state_config=link_state_config,
            protocol_name="PMAP_ACK" if d2z_ack_mode else "PMAP",
            analysis_family="D2Z",
        )

        UAVSessionTrackerMixin._init_session_tracker(self, session_tracker)

        self.attack_model = attack_model if attack_model is not None else {}
        self.d2z_ack_mode = bool(d2z_ack_mode)
        self._d2z_pending_commit = None
        self._d2z_ack_deadline_gen = 0
        self._d2z_m2_deadline_gen = 0
        self._d2z_attempt_counter = 0
        self._d2z_attempt_session_id = None
        self._current_session_id = None
        self._current_subsession_id = 0

        self.chaotic = ChaoticMap()
        self.puf = PUFGenerator(uav_id)

        self.zsp_id = None

        self.crp = [None, None]
        self.new_crp = [None, None]
        self.crp[0] = 0.1 + uav_id * 0.01
        self.crp[1] = self.puf.generate_response(self.crp[0])
        self.pid = hash_256(str(self.id) + str(self.crp[1]))

        self.ni = None
        self.ns = None
        self.session_key = None
        self.D2D_sessions = {}

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
            self._current_session_id = sid
            self._d2z_attempt_counter = 0
            self._current_subsession_id = 0

    def _can_trigger_d2z_auth(self) -> bool:
        if not super()._can_trigger_d2z_auth():
            return False
        if self.d2z_ack_mode and self._d2z_pending_commit is not None:
            return False
        return True

    def _send_M1_retry(self, retry_reason):
        max_attempts = self._max_d2z_attempts()
        if max_attempts is not None and self._d2z_attempt_counter >= max_attempts:
            self._track_session_end(success=False, error_reason="retry_budget_exhausted", is_timeout=True)
            return

        if self._d2z_attempt_counter == 0:
            self._refresh_attempt_scope()
            self._current_subsession_id = 1
        else:
            self._current_subsession_id += 1

        self._d2z_attempt_counter += 1

        self._track_session_start(trigger_step=f"D2Z_RETRY_{retry_reason}", is_retry=True)
        self._register_pid_mapping()
        self._update_protocol_state(SessionTracker.ProtocolState.M1_SEND, message_type="M1")

        self.ni = random.random()
        plaintext = PMAPPlaintext.encode(
            PMAPPlaintext.M1,
            self.pid,
            self.zsp_id,
            self.ni
        )

        encrypted = self.chaotic.encrypt_by_crp(plaintext, self.crp)
        mac_input = encrypted + struct.pack(">d", self.ni)
        packet = PMAPPacket.build(
            PMAPMessageType.M1,
            self.pid,
            encrypted,
            mac_input
        )

        if not self.SendData(packet, "M1"):
            delay = self.attack_model.get("d2z_retry_delay_s", 0.5)
            self._safe_schedule(delay, self._send_M1_retry, "m1_dropped")
        else:
            self._d2z_m2_deadline_gen += 1
            timeout = self.attack_model.get("d2z_ack_timeout_s", 5.0)
            g = self._d2z_m2_deadline_gen
            self._safe_schedule(timeout, self._d2z_m2_timeout, g)

        self._track_message("M1", len(packet), direction="send")

    def _d2z_m2_timeout(self, gen: int):
        if gen != self._d2z_m2_deadline_gen:
            return
        self._send_M1_retry("timeout")

    def D2Z_InitiateAuth(self):
        self._refresh_attempt_scope()
        max_attempts = self._max_d2z_attempts()
        if max_attempts is not None and self._d2z_attempt_counter >= max_attempts:
            self._track_session_end(success=False, error_reason="retry_budget_exhausted", is_timeout=True)
            return

        self._track_session_start(trigger_step="D2Z_INITIATED")

        if hasattr(self, 'zsp_addr') and self.zsp_addr is not None:
            self.Connect(self.zsp_addr)

        self._register_pid_mapping()
        self._update_protocol_state(SessionTracker.ProtocolState.M1_SEND, message_type="M1")

        self.ni = random.random()
        plaintext = PMAPPlaintext.encode(
            PMAPPlaintext.M1,
            self.pid,
            self.zsp_id,
            self.ni
        )

        encrypted = self.chaotic.encrypt_by_crp(plaintext, self.crp)
        mac_input = encrypted + struct.pack(">d", self.ni)
        packet = PMAPPacket.build(
            PMAPMessageType.M1,
            self.pid,
            encrypted,
            mac_input
        )

        if not self.SendData(packet, "M1"):
            self._track_message("M1", len(packet), direction="send")
            self._track_error("uplink_loss", "M1 dropped", message_type="M1")
            delay = self.attack_model.get("d2z_retry_delay_s", 0.5)
            self._safe_schedule(delay, self._send_M1_retry, "m1_dropped")
        else:
            self._track_message("M1", len(packet), direction="send")
            self._d2z_m2_deadline_gen += 1
            timeout = self.attack_model.get("d2z_ack_timeout_s", 5.0)
            g = self._d2z_m2_deadline_gen
            self._safe_schedule(timeout, self._d2z_m2_timeout, g)

    def D2D_InitiateAuth(self, target_pid):
        session = D2D_Session()
        session.ni = random.random()
        self.D2D_sessions[target_pid] = session

        m1_plain = PMAPPlaintext.encode(PMAPPlaintext.D2D_M1, self.pid, self.zsp_id, session.ni)
        m2_plain = PMAPPlaintext.encode(PMAPPlaintext.D2D_M2, self.pid, self.zsp_id, session.ni, target_pid)

        enc1 = self.chaotic.encrypt_by_crp(m1_plain, self.crp)
        enc2 = self.chaotic.encrypt_by_crp(m2_plain, self.crp)
        payload = enc1 + enc2
        mac_input = payload + struct.pack(">d", session.ni) + bytes.fromhex(target_pid)

        packet = PMAPPacket.build(PMAPMessageType.D2D_M1_2, self.pid, payload, mac_input)
        self.SendData(packet, "D2D M1/2")

    def ProcessReceivedData(self, packet_bytes):
        packet_bytes = bytes(packet_bytes)
        ack_wire = PMAPPacket.d2z_ack_wire_len()

        if self.d2z_ack_mode and len(packet_bytes) > ack_wire and packet_bytes[0] == PMAPMessageType.D2Z_ACK:
            self._handle_d2z_ack(packet_bytes[:ack_wire])
            tail = packet_bytes[ack_wire:]
            if tail:
                self.ProcessReceivedData(tail)
            return

        try:
            if len(packet_bytes) < PMAPPacket.HEADER_STRUCT.size + 32:
                return
            msg_type, pid, payload, mac = PMAPPacket.parse(packet_bytes)

            if msg_type == PMAPMessageType.D2Z_ACK and self.d2z_ack_mode:
                self._handle_d2z_ack(packet_bytes)
                return

            if pid != self.pid:
                return

            if msg_type == PMAPMessageType.M2:
                self._handle_M2(pid, payload, packet_bytes)

            elif msg_type == PMAPMessageType.D2D_M3:
                self._handle_D2D_M3(pid, payload)

            elif msg_type == PMAPMessageType.D2D_M6_7_8:
                self._handle_D2D_M6_7_8(pid, payload)

            elif msg_type == PMAPMessageType.D2D_M11:
                self._handle_D2D_M11(pid, payload)

        except Exception:
            pass

    def _handle_M2(self, pid, payload, packet_bytes):
        self._d2z_m2_deadline_gen += 1
        self._d2z_pending_commit = None
        self._d2z_ack_deadline_gen += 1

        try:
            plaintext = self.chaotic.decrypt_by_crp(payload, self.crp)
            pid, zsp, ni, ns = PMAPPlaintext.decode(PMAPPlaintext.M2, plaintext)
        except Exception:
            self._track_error("decryption_failed", "M2 decryption failed", message_type="M2")
            self._update_protocol_state(SessionTracker.ProtocolState.FAILED_CRP,
                                      message_type="M2", error_type="decryption_failed",
                                      error_reason="M2 CRP decryption failed")
            self._track_session_end(success=False, error_reason="m2_decryption_failed", is_timeout=False)
            return

        if ni != self.ni:
            self._track_error("nonce_mismatch", "M2 nonce mismatch", message_type="M2")
            self._update_protocol_state(SessionTracker.ProtocolState.FAILED_NONCE,
                                      message_type="M2", error_type="nonce_mismatch",
                                      error_reason="M2 nonce mismatch")
            self._track_session_end(success=False, error_reason="m2_nonce_mismatch", is_timeout=False)
            return

        self._track_message("M2", len(packet_bytes), direction="receive")
        self._update_protocol_state(SessionTracker.ProtocolState.M2_RECEIVE, message_type="M2")
        self.ns = ns
        self._send_M3_M4()

    def _handle_D2D_M3(self, pid, payload):
        plain = self.chaotic.decrypt_by_crp(payload, self.crp)
        pid_i, zsp, pid_j, ni, n1 = PMAPPlaintext.decode(PMAPPlaintext.D2D_M3, plain)

        session = self.D2D_sessions.get(pid_j)
        if session is None or ni != session.ni:
            return

        session.n1 = n1
        session.ni = random.random()

        m4_plain = PMAPPlaintext.encode(PMAPPlaintext.D2D_M4, self.pid, self.zsp_id, pid_j, n1, session.ni)

        seed = self.chaotic.encrypt_by_crp(str(session.n1).encode() + str(session.ni).encode(), self.crp)
        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        challenge = canonicalize_scalar(challenge)
        response = self.puf.generate_response(challenge)
        response = canonicalize_scalar(response)
        self.new_crp = [challenge, response]

        m5_plain = PMAPPlaintext.encode(PMAPPlaintext.D2D_M5, self.pid, self.zsp_id, pid_j, n1, session.ni, response)

        enc4 = self.chaotic.encrypt_by_crp(m4_plain, self.crp)
        enc5 = self.chaotic.encrypt_by_crp(m5_plain, self.crp)
        mac_input = enc4 + enc5 + struct.pack(">d", session.ni) + struct.pack(">d", response)
        packet = PMAPPacket.build(PMAPMessageType.D2D_M4_5, self.pid, enc4 + enc5, mac_input)

        self.SendData(packet, "D2D M4/5")

    def _handle_D2D_M6_7_8(self, pid, payload):
        size6 = PMAPPlaintext.D2D_M6.size
        size7 = PMAPPlaintext.D2D_M7.size

        enc6 = payload[:size6]
        enc7 = payload[size6:size6 + size7]
        enc8 = payload[size6 + size7:]

        m6 = self.chaotic.decrypt_by_crp(enc6, self.crp)
        m7 = self.chaotic.decrypt_by_crp(enc7, self.crp)
        m8 = self.chaotic.decrypt_by_crp(enc8, self.crp)

        _, zsp, n2 = PMAPPlaintext.decode(PMAPPlaintext.D2D_M6, m6)
        _, _, _, ni = PMAPPlaintext.decode(PMAPPlaintext.D2D_M7, m7)
        _, _, _, _, pid_i = PMAPPlaintext.decode(PMAPPlaintext.D2D_M8, m8)

        session = D2D_Session()
        session.n2 = n2
        session.ni = ni
        session.nj = random.random()
        self.D2D_sessions[pid_i] = session

        seed = self.chaotic.encrypt_by_crp(str(n2).encode() + str(session.nj).encode(), self.crp)
        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        challenge = canonicalize_scalar(challenge)
        response = self.puf.generate_response(challenge)
        response = canonicalize_scalar(response)

        m9_plain = PMAPPlaintext.encode(PMAPPlaintext.D2D_M9, self.pid, self.zsp_id, pid_i, n2, session.nj)
        m10_plain = PMAPPlaintext.encode(PMAPPlaintext.D2D_M10, self.pid, self.zsp_id, pid_i, n2, session.nj, response)

        enc9 = self.chaotic.encrypt_by_crp(m9_plain, self.crp)
        enc10 = self.chaotic.encrypt_by_crp(m10_plain, self.crp)
        mac_input = enc9 + enc10 + struct.pack(">d", session.nj) + struct.pack(">d", response)
        packet = PMAPPacket.build(PMAPMessageType.D2D_M9_10, self.pid, enc9 + enc10, mac_input)

        self.SendData(packet, "D2D M9/10")
        self.crp = [challenge, response]
        _old_pid = self.pid
        self.pid = hash_256(str(self.id) + str(response))
        self._desync_notify_local_pid(_old_pid, self.pid, "d2d_pid_roll")

        session.session_key = int(hash_256(str(session.ni)), 16) ^ int(hash_256(str(session.nj)), 16)

    def _handle_D2D_M11(self, pid, payload):
        plaintext = self.chaotic.decrypt_by_crp(payload, self.crp)
        pid_j, zsp, pid_i, ni, nj = PMAPPlaintext.decode(PMAPPlaintext.D2D_M11, plaintext)

        session = self.D2D_sessions.get(pid_i)
        if session is None:
            return

        session.nj = nj
        session.session_key = int(hash_256(str(ni)), 16) ^ int(hash_256(str(nj)), 16)

        new_pid = hash_256(str(self.id) + str(self.new_crp[1]))
        _old_pid = self.pid
        self.pid = new_pid
        self._desync_notify_local_pid(_old_pid, self.pid, "d2d_m11_pid")
        self.crp = self.new_crp

    def _on_d2z_m34_aborted(self):
        max_attempts = self._max_d2z_attempts()
        if max_attempts is not None and self._d2z_attempt_counter >= max_attempts:
            self._track_session_end(success=False, error_reason="retry_budget_exhausted", is_timeout=True)
            return
        delay = self.attack_model.get("d2z_retry_delay_s", 0.5)
        self._safe_schedule(delay, self._send_M1_retry, "m34_aborted")

    def _d2z_ack_deadline(self, gen: int):
        if gen != self._d2z_ack_deadline_gen:
            return
        if self._d2z_pending_commit is None:
            return
        self._d2z_pending_commit = None
        max_attempts = self._max_d2z_attempts()
        if max_attempts is not None and self._d2z_attempt_counter >= max_attempts:
            self._track_session_end(success=False, error_reason="retry_budget_exhausted", is_timeout=True)
            return
        self.authenticated = False
        self._send_M1_retry("ack_timeout")

    def _handle_d2z_ack(self, packet_bytes: bytes):
        if not self._d2z_pending_commit:
            return
        packet_bytes = bytes(packet_bytes)
        ack_wire = PMAPPacket.d2z_ack_wire_len()
        if len(packet_bytes) > ack_wire and packet_bytes and packet_bytes[0] == PMAPMessageType.D2Z_ACK:
            packet_bytes = packet_bytes[:ack_wire]

        try:
            msg_type, hdr_pid, payload, mac_hex = PMAPPacket.parse(packet_bytes)
        except Exception:
            return

        if msg_type != PMAPMessageType.D2Z_ACK:
            return

        ack_plain_size = PMAPPlaintext.D2Z_ACK.size
        if len(payload) != ack_plain_size:
            return

        pend = self._d2z_pending_commit
        if d2z_mac_hex(payload, [struct.pack(">d", pend["ni"]), struct.pack(">d", pend["response"])]) != mac_hex:
            return

        plain = self.chaotic.decrypt_by_crp(payload, self.crp)
        if len(plain) != ack_plain_size:
            return

        try:
            old_b, new_b, ch, resp = PMAPPlaintext.decode(PMAPPlaintext.D2Z_ACK, plain)
        except struct.error:
            return

        old_pid_wire = PMAPPlaintext.bytes_to_pid(old_b)
        new_pid_wire = PMAPPlaintext.bytes_to_pid(new_b)

        if old_pid_wire != self.pid:
            return
        if new_pid_wire != pend["new_pid"]:
            return
        if abs(float(ch) - float(pend["new_crp"][0])) > 1e-9 or abs(float(resp) - float(pend["new_crp"][1])) > 1e-9:
            return

        self._d2z_ack_deadline_gen += 1
        self._d2z_pending_commit = None

        _old_pid = self.pid
        self.pid = pend["new_pid"]
        self._desync_notify_local_pid(_old_pid, self.pid, "pmap_ack_apply")
        self.crp = pend["new_crp"]
        self.session_key = pend["session_key"]

        self._update_protocol_state(SessionTracker.ProtocolState.ACK_RECEIVE, message_type="ACK")
        key_hash = hex(self.session_key)[2:]
        self._track_session_key(key_hash)
        self._track_session_end(success=True)
        self.authenticated = True

    def _send_M3_M4(self):
        try:
            self.ni = random.random()
            seed = self.chaotic.encrypt_by_crp(str(self.ni).encode() + str(self.ns).encode(), self.crp)
            challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
            challenge = canonicalize_scalar(challenge)
            response = self.puf.generate_response(challenge)
            response = canonicalize_scalar(response)

            m3_plain = PMAPPlaintext.encode(PMAPPlaintext.M3, self.pid, self.zsp_id, self.ns, self.ni)
            m4_plain = PMAPPlaintext.encode(PMAPPlaintext.M4, self.pid, self.zsp_id, self.ns, self.ni, response)

            enc3 = self.chaotic.encrypt_by_crp(m3_plain, self.crp)
            enc4 = self.chaotic.encrypt_by_crp(m4_plain, self.crp)

            mac_input = enc3 + enc4 + struct.pack(">d", self.ni) + struct.pack(">d", response)
            packet = PMAPPacket.build(PMAPMessageType.M3_4, self.pid, enc3 + enc4, mac_input)

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
                t = float(self.attack_model.get("d2z_ack_timeout_s", 5.0))
                self._d2z_ack_deadline_gen += 1
                g = self._d2z_ack_deadline_gen
                self._safe_schedule(t, self._d2z_ack_deadline, g)
            else:
                self.crp = [challenge, response]
                _old_pid = self.pid
                self.pid = new_pid
                self._desync_notify_local_pid(_old_pid, self.pid, "pmap_post_m3m4_local")
                self.session_key = session_key

                key_hash = hex(self.session_key)[2:]
                self.authenticated = True
                self._track_session_key(key_hash)

            if not self.SendData(packet, "M3_M4"):
                self._on_d2z_m34_aborted()
                return

            self._track_message("M3_M4", len(packet), direction="send")
            self._update_protocol_state(SessionTracker.ProtocolState.M3_M4_SEND, message_type="M3_M4")

            if not self.d2z_ack_mode:
                self._update_protocol_state(SessionTracker.ProtocolState.SUCCESS, message_type="M3_M4")

        except Exception:
            pass

    def on_connected_to_zsp(self):
        def logic():
            if self.auth_trigger_config.get("initial_on_connect", True):
                self._trigger_d2z_auth("D2Z_INITIATED")
        self._safe_execute("on_connected", logic)

    def _attack_simulate_d2z_timeout_retry(self):
        if self.d2z_ack_mode:
            return
        if not self.attack_model.get("intercept_m3_m4_delivery"):
            return
        if self.authenticated:
            return
        self.authenticated = False
        self.D2Z_InitiateAuth()