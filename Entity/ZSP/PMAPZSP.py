"""
PMAP协议ZSP实现
"""

import struct
import random
import hashlib
import uuid
from collections import defaultdict
from typing import Optional
from ns import ns

from Common.logging_framework import DatabaseOperation, IdentifierOperation
from Common.crp_chain_codec import canonicalize_crp_pair
from Entity.ZSP.BaseZSP import BaseZSP
from Entity.common.session_tracker_mixin import ZSPSessionTrackerMixin
from Caculator.ChaoticMap import ChaoticMap
from Caculator.Hash import hash_256
from Simulator.session_tracker import SessionTracker
from Protocol.PMAP.PMAPPlaintext import PMAPPlaintext as PMAP
from Protocol.PMAP.Packet import PMAPPacket
from Protocol.PMAP.MsgType import PMAPMessageType
from Protocol.PMAP.pmap_common import D2Z_Session, D2D_Session, PMAPMacHelper


class PMAP_ZSP(BaseZSP, ZSPSessionTrackerMixin):

    def __init__(
        self,
        node,
        zsp_id,
        blockchain=None,
        enable_blockchain=False,
        attack_model=None,
        d2z_ack_mode: bool = False,
        compute_profile=None,
        session_tracker=None,
    ):

        super().__init__(
            node,
            zsp_id,
            blockchain,
            enable_blockchain,
            protocol_name="PMAP_ACK" if d2z_ack_mode else "PMAP",
            analysis_family="D2Z",
        )

        ZSPSessionTrackerMixin._init_session_tracker(self, session_tracker)

        self.attack_model = attack_model if attack_model is not None else {}
        self.d2z_ack_mode = bool(d2z_ack_mode)
        self.compute_profile = dict(compute_profile or {})

        self.chaotic = ChaoticMap()

        self.D2Z_sessions = {}
        self.D2D_sessions = {}
        self.crp = [None, None]

        self._desync_m3m4_drop_uavs = set()
        self._desync_ack_suppress_uavs = set()
        self._desync_m3m4_anonymous_drop_used = False
        self._desync_ack_anonymous_suppress_used = False
        self._desync_uav_completed_d2z = defaultdict(int)
        self._desync_uav_attempted_d2z = defaultdict(int)
        self._ack_pending_transition = {}

    def _response_delay_s(self) -> float:
        return float(self.compute_profile.get("response_delay_s", 0.0) or 0.0)

    def _send_response_with_compute_delay(self, packet: bytes, dest_addr, uav_id: Optional[int] = None):
        delay = self._response_delay_s()
        if delay > 0:
            self._safe_schedule(delay, self._send_response_and_track, packet, dest_addr, uav_id)
            return
        self._send_response_and_track(packet, dest_addr, uav_id)
    
    def _send_response_and_track(self, packet: bytes, dest_addr, uav_id: Optional[int] = None):
        self.SendResponse(packet, dest_addr)
        if uav_id is not None and len(packet) >= 2:
            msg_type = packet[1]
            if msg_type == 2:
                self._track_message(uav_id, "M2", len(packet), direction="send")
                self._update_protocol_state(uav_id, SessionTracker.ProtocolState.M2_SEND, message_type="M2")
            elif msg_type == 4:
                self._track_message(uav_id, "D2Z_ACK", len(packet), direction="send")

    def _desync_first_auth_only(self) -> bool:
        return bool(self.attack_model.get("desync_attack_first_auth_only", False))

    def _desync_min_completed_sessions(self) -> int:
        try:
            return max(0, int(self.attack_model.get("desync_attack_min_completed_sessions") or 0))
        except (TypeError, ValueError):
            return 0

    def _desync_max_completed_sessions(self) -> Optional[int]:
        try:
            val = self.attack_model.get("desync_attack_max_completed_sessions")
            if val is None:
                return None
            return max(0, int(val))
        except (TypeError, ValueError):
            return None

    def _desync_attack_session_gate_open(self, pid: str) -> bool:
        uid = self.uav_db.get(pid, {}).get("uav_id")
        if uid is None:
            return True

        min_c = self._desync_min_completed_sessions()
        max_c = self._desync_max_completed_sessions()
        completed = int(self._desync_uav_completed_d2z.get(uid, 0))

        if max_c is not None and max_c >= min_c:
            attempted = int(self._desync_uav_attempted_d2z.get(uid, 0))
            if completed < min_c or attempted <= min_c or attempted > max_c:
                return False
            return True

        if completed < min_c:
            return False
        if max_c is not None and completed > max_c:
            return False
        return True

    def _note_d2z_success_for_desync_counter(self, pid: str) -> None:
        rec = self.uav_db.get(pid) or {}
        uid = rec.get("uav_id")
        if uid is not None:
            self._desync_uav_completed_d2z[int(uid)] += 1

    def _consume_m3m4_drop_desync(self, pid: str) -> bool:
        if not self.attack_model.get("intercept_m3_m4_delivery"):
            return False
        if not self._desync_attack_session_gate_open(pid):
            return False
        if self._desync_first_auth_only():
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
        if not self.attack_model.get("intercept_d2z_ack_send"):
            return False
        if not self._desync_attack_session_gate_open(pid):
            return False
        if self._desync_first_auth_only():
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

    def _ack_grace_window_s(self) -> float:
        timeout = float(self.attack_model.get("d2z_ack_timeout_s", 5.0) or 5.0)
        attempts = int(self.attack_model.get("max_d2z_attempts", 2) or 2)
        return max(5.0, timeout * max(1, attempts) + 2.0)

    def _cleanup_expired_ack_transitions(self) -> None:
        if not self._ack_pending_transition:
            return
        now = ns.Simulator.Now().GetSeconds()
        expired = [old_pid for old_pid, st in self._ack_pending_transition.items() if now >= st.get("expires_at", 0.0)]
        for old_pid in expired:
            self._ack_pending_transition.pop(old_pid, None)

    def _stage_ack_transition(
        self,
        old_pid: str,
        new_pid: str,
        challenge: float,
        response: float,
        session_key: int,
    ) -> None:
        if old_pid not in self.uav_db:
            return
        old_info = dict(self.uav_db[old_pid])
        new_info = dict(old_info)
        new_info["pid"] = new_pid
        new_info["crp"] = [challenge, response]
        self.uav_db[new_pid] = new_info
        self._ack_pending_transition[old_pid] = {
            "new_pid": new_pid,
            "new_crp": [challenge, response],
            "challenge": challenge,
            "response": response,
            "session_key": session_key,
            "expires_at": ns.Simulator.Now().GetSeconds() + self._ack_grace_window_s(),
        }

    def _commit_ack_transition_if_confirmed(self, pid: str) -> bool:
        for old_pid, st in list(self._ack_pending_transition.items()):
            new_pid = st.get("new_pid")
            if pid == new_pid:
                if old_pid in self.uav_db:
                    self.uav_db.pop(old_pid, None)
                if self.enable_blockchain and self.blockchain:
                    try:
                        self.blockchain.update_pid(old_pid, new_pid, st["challenge"], st["response"])
                    except Exception:
                        pass
                self._ack_pending_transition.pop(old_pid, None)
                return True

        for old_pid, st in list(self._ack_pending_transition.items()):
            new_pid = st.get("new_pid")
            if pid == old_pid:
                if new_pid in self.uav_db:
                    self.uav_db.pop(new_pid, None)
                self._ack_pending_transition.pop(old_pid, None)
                return True
        return False

    def ProcessRequest(self, buf, from_addr):
        wire_len = len(buf)
        msg_type, pid, payload, mac = PMAPPacket.parse(buf)

        if msg_type == PMAPMessageType.M1:
            self.handle_M1(pid, payload, mac, from_addr, wire_len)

        elif msg_type == PMAPMessageType.M3_4:
            if self._consume_m3m4_drop_desync(pid):
                return
            self.handle_M3_4(pid, payload, mac, from_addr, wire_len)

        elif msg_type == PMAPMessageType.D2D_M1_2:
            self.handle_D2D_M1_2(pid, payload, mac, from_addr)

        elif msg_type == PMAPMessageType.D2D_M4_5:
            self.handle_D2D_M4_5(pid, payload, mac, from_addr)

        elif msg_type == PMAPMessageType.D2D_M9_10:
            self.handle_D2D_M9_10(pid, payload, mac, from_addr)

    def handle_M1(self, pid, payload, mac, from_addr, wire_len: int):
        if self.d2z_ack_mode:
            self._commit_ack_transition_if_confirmed(pid)
        self._cleanup_expired_ack_transitions()

        if pid not in self.uav_db:
            self._handle_unknown_pid_M1(pid, wire_len)
            return

        rec = self.uav_db.get(pid) or {}
        uav_id = rec.get("uav_id")
        if uav_id is not None:
            self._desync_uav_attempted_d2z[int(uav_id)] += 1

        crp = self.uav_db[pid]["crp"]
        decrypted = self.chaotic.decrypt_by_crp(payload, crp)
        m1 = PMAP.decode(PMAP.M1, decrypted)
        ni = m1[2]

        if not PMAPMacHelper.verify_mac(payload, [struct.pack(">d", ni)], mac):
            if uav_id is not None:
                self._track_error(uav_id, "mac_verification_failed", "M1 MAC verification failed", message_type="M1")
                self._update_protocol_state(uav_id, SessionTracker.ProtocolState.FAILED_MAC,
                                          message_type="M1", error_type="mac_verification_failed",
                                          error_reason="M1 MAC verification failed")
            return

        ns_val = random.random()
        session = D2Z_Session()
        session.ni = ni
        session.ns = ns_val
        session.from_addr = from_addr
        self.D2Z_sessions[pid] = session

        plaintext = bytes.fromhex(pid) + struct.pack(">I", self.zsp_id) + struct.pack(">d", ni) + struct.pack(">d", ns_val)
        encrypted = self.chaotic.encrypt_by_crp(plaintext, crp)
        mac_val = hashlib.sha256(encrypted + struct.pack(">d", session.ni) + struct.pack(">d", ns_val)).hexdigest()

        packet = PMAPPacket.build(
            PMAPMessageType.M2,
            pid,
            encrypted,
            encrypted + struct.pack(">d", session.ni) + struct.pack(">d", ns_val)
        )

        if uav_id is not None:
            self._track_message(uav_id, "M1", wire_len, direction="receive")
        self._update_protocol_state(uav_id, SessionTracker.ProtocolState.M1_RECEIVE, message_type="M1", pid=pid)
        
        self._update_protocol_state(uav_id, SessionTracker.ProtocolState.M2_SEND, message_type="M2", pid=pid)

        self._send_response_with_compute_delay(packet, from_addr, uav_id=uav_id if uav_id else None)

    def _handle_unknown_pid_M1(self, pid: str, wire_len: int):
        tracker = self._get_session_tracker()
        sim_time = ns.Simulator.Now().GetSeconds()

        if tracker:
            try:
                tracker.record_error(
                    auth_session_id=None,
                    error_type="unknown_pid_received",
                    error_reason=f"M1 received with unknown PID {pid} at ZSP {self.zsp_id}",
                    sim_time=sim_time,
                    message_type="M1",
                )
                session_info = tracker.resolve_session_by_pid(pid)

                if session_info:
                    auth_session_id = session_info.auth_session_id
                    tracker.update_protocol_state(
                        auth_session_id=auth_session_id,
                        new_state=SessionTracker.ProtocolState.FAILED_PID,
                        sim_time=sim_time,
                        message_type="M1",
                        error_type="invalid_pid",
                        error_reason="PID not found in ZSP uav_db",
                    )
                    tracker.record_error(
                        auth_session_id=auth_session_id,
                        error_type="invalid_pid",
                        error_reason="M1 received with invalid PID",
                        sim_time=sim_time,
                        message_type="M1",
                    )
                    tracker.end_session(
                        auth_session_id=auth_session_id,
                        sim_time=sim_time,
                        success=False,
                        error_reason="PID not found in ZSP uav_db",
                        is_timeout=False,
                    )
                else:
                    uav_zsp_pair = tracker.resolve_pid(pid)
                    if uav_zsp_pair:
                        uav_id, zsp_id = uav_zsp_pair
                        session_id = tracker.get_session_id_by_pair(uav_id, zsp_id)
                        if session_id:
                            tracker.update_protocol_state(
                                auth_session_id=session_id,
                                new_state=SessionTracker.ProtocolState.FAILED_PID,
                                sim_time=sim_time,
                                message_type="M1",
                                error_type="invalid_pid",
                                error_reason="PID not found in ZSP uav_db",
                            )
                            tracker.record_error(
                                auth_session_id=session_id,
                                error_type="invalid_pid",
                                error_reason="M1 received with invalid PID",
                                sim_time=sim_time,
                                message_type="M1",
                            )
                            tracker.end_session(
                                auth_session_id=session_id,
                                sim_time=sim_time,
                                success=False,
                                error_reason="PID not found in ZSP uav_db",
                                is_timeout=False,
                            )
                    else:
                        tracker.record_error(
                            auth_session_id=None,
                            error_type="invalid_pid",
                            error_reason="M1 received with invalid PID, session not found",
                            sim_time=sim_time,
                            message_type="M1",
                        )
            except Exception:
                pass

    def handle_M3_4(self, pid, payload, mac, from_addr, wire_len: int):
        if pid not in self.uav_db:
            return

        crp = self.uav_db[pid]["crp"]
        uav_id = self.uav_db[pid].get("uav_id")

        m3_size = PMAP.M3.size
        m4_size = PMAP.M4.size
        enc3 = payload[:m3_size]
        enc4 = payload[m3_size:m3_size + m4_size]

        try:
            plain3 = self.chaotic.decrypt_by_crp(enc3, crp)
            plain4 = self.chaotic.decrypt_by_crp(enc4, crp)
            m3 = PMAP.decode(PMAP.M3, plain3)
            m4 = PMAP.decode(PMAP.M4, plain4)
        except Exception:
            if uav_id is not None:
                self._track_error(uav_id, "decryption_failed", "M3/M4 decryption failed", message_type="M3_M4")
            return

        ni = m3[3]
        response = m4[4]
        session = self.D2Z_sessions.get(pid)
        if session is None:
            return
        
        session.ni = ni
        session_key = int(hash_256(str(ni)), 16) ^ int(hash_256(str(session.ns)), 16)
        session.session_key = session_key

        if not PMAPMacHelper.verify_mac(payload, [struct.pack(">d", session.ni), struct.pack(">d", response)], mac):
            if uav_id is not None:
                self._track_error(uav_id, "mac_verification_failed", "M3/M4 MAC verification failed", message_type="M3_M4")
                self._update_protocol_state(uav_id, SessionTracker.ProtocolState.FAILED_MAC,
                                          message_type="M3_M4", error_type="mac_verification_failed",
                                          error_reason="M3/M4 MAC verification failed")
            return

        seed = self.chaotic.encrypt_by_crp(str(session.ni).encode() + str(session.ns).encode(), crp)
        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        challenge, response = canonicalize_crp_pair(challenge, response)
        new_pid = hash_256(str(self.uav_db[pid]["uav_id"]) + str(response))

        if uav_id is not None:
            self._track_message(uav_id, "M3_M4", wire_len, direction="receive")
            self._track_session_key(uav_id, str(session_key), f"zsp_session_{self.zsp_id}_{uav_id}")
        self._update_protocol_state(uav_id, SessionTracker.ProtocolState.M3_M4_RECEIVE, message_type="M3_M4", pid=pid)

        if not self.d2z_ack_mode:
            self._d2z_finalize_commit(pid, new_pid, challenge, response, session_key, session, old_crp=crp)
            if uav_id is not None:
                self._track_session_end(uav_id, success=True)
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
            return

        self._update_protocol_state(uav_id, SessionTracker.ProtocolState.ACK_SEND, message_type="ACK", pid=pid)

        self._send_response_with_compute_delay(ack_packet, session.from_addr, uav_id=uav_id if uav_id else None)
        self._stage_ack_transition(
            old_pid=pid,
            new_pid=new_pid,
            challenge=challenge,
            response=response,
            session_key=session_key,
        )
        self._note_d2z_success_for_desync_counter(new_pid)

    def _d2z_finalize_commit(
        self,
        old_pid: str,
        new_pid: str,
        challenge: float,
        response: float,
        session_key: int,
        session: D2Z_Session,
        old_crp,
    ) -> None:
        self.UpdateUAVPID(old_pid, new_pid, challenge, response)
        self.D2Z_sessions[new_pid] = self.D2Z_sessions.pop(old_pid)
        self._note_d2z_success_for_desync_counter(new_pid)

    def handle_D2D_M1_2(self, pid, payload, mac, from_addr):
        if pid not in self.uav_db:
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

        if not PMAPMacHelper.verify_mac(payload, [struct.pack(">d", ni), struct.pack(">32s", bytes.fromhex(pid_j))], mac):
            return

        session = D2D_Session()
        session.ni = ni
        session.n1 = random.random()
        session.n2 = random.random()
        session.from_addr = from_addr
        session.to_addr = self.D2Z_sessions[pid_j].from_addr
        self.D2D_sessions[pid + pid_j] = session

        m3 = PMAP.encode(PMAP.D2D_M3, pid, self.zsp_id, pid_j, ni, session.n1)
        encrypted = self.chaotic.encrypt_by_crp(m3, self.uav_db[pid]["crp"])
        mac_input = encrypted + struct.pack(">d", ni) + struct.pack(">d", session.n1)

        packet = PMAPPacket.build(PMAPMessageType.D2D_M3, pid, encrypted, mac_input)
        self._send_response_with_compute_delay(packet, from_addr)

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

        if not PMAPMacHelper.verify_mac(payload, [struct.pack(">d", ni), struct.pack(">d", response)], mac):
            return

        session = self.D2D_sessions.get(pid + pid_j)
        if session is None:
            return
        
        session.ni = ni

        m6 = PMAP.encode(PMAP.D2D_M6, pid_j, self.zsp_id, session.n2)
        m7 = PMAP.encode(PMAP.D2D_M7, pid_j, self.zsp_id, session.n2, ni)
        m8 = PMAP.encode(PMAP.D2D_M8, pid_j, self.zsp_id, session.n2, ni, pid)

        uav_data = self.uav_db[pid_j]["crp"]
        encrypted_6 = self.chaotic.encrypt_by_crp(m6, uav_data)
        encrypted_7 = self.chaotic.encrypt_by_crp(m7, uav_data)
        encrypted_8 = self.chaotic.encrypt_by_crp(m8, uav_data)

        encrypted = encrypted_6 + encrypted_7 + encrypted_8
        mac_input = encrypted + struct.pack(">d", session.n2) + struct.pack(">d", session.ni)

        packet = PMAPPacket.build(PMAPMessageType.D2D_M6_7_8, pid_j, encrypted, mac_input)
        self._send_response_with_compute_delay(packet, session.to_addr)

        seed = self.chaotic.encrypt_by_crp(
            str(session.n1).encode() + str(session.ni).encode(),
            self.uav_db[pid]["crp"]
        )
        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        challenge, response = canonicalize_crp_pair(challenge, response)
        self.crp = [challenge, response]

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

        if not PMAPMacHelper.verify_mac(payload, [struct.pack(">d", nj), struct.pack(">d", response)], mac):
            return

        session = self.D2D_sessions.get(pid_i + pid)
        if session is None:
            return
        
        session.nj = nj

        m11 = PMAP.encode(PMAP.D2D_M11, pid_i, self.zsp_id, pid, session.ni, session.nj)
        encrypted = self.chaotic.encrypt_by_crp(m11, self.uav_db[pid_i]["crp"])
        mac_input = encrypted + struct.pack(">d", session.ni) + struct.pack(">d", session.nj)
        session_key = int(hash_256(str(session.ni)), 16) ^ int(hash_256(str(session.nj)), 16)
        session.session_key = session_key

        packet = PMAPPacket.build(PMAPMessageType.D2D_M11, pid_i, encrypted, mac_input)
        self._send_response_with_compute_delay(packet, session.from_addr)

        seed = self.chaotic.encrypt_by_crp(
            str(session.n2).encode() + str(session.nj).encode(),
            self.crp
        )
        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        new_pid = hash_256(str(self.uav_db[pid]["uav_id"]) + str(response))
        self.UpdateUAVPID(pid, new_pid, challenge, response)

        new_pid_i = hash_256(str(self.uav_db[pid_i]["uav_id"]) + str(self.crp[1]))
        self.UpdateUAVPID(pid_i, new_pid_i, self.crp[0], self.crp[1])