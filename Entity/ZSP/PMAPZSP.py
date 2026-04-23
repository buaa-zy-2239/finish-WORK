import struct
import random
import hashlib
import uuid
from collections import defaultdict
from typing import Optional
from ns import ns

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
        self.zsp_session_id = str(uuid.uuid4())
        self.subsession_id = None  # 子会话ID，用于区分不同的重试会话
        self.auth_session_id = None  # UAV侧的auth_session_id，用于关联UAV和ZSP的事件


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
        compute_profile=None,
    ):

        super().__init__(
            node,
            zsp_id,
            blockchain,
            enable_blockchain,
            protocol_name="PMAP_ACK" if d2z_ack_mode else "PMAP",
            analysis_family="D2Z",
        )

        self.attack_model = attack_model if attack_model is not None else {}
        self.d2z_ack_mode = bool(d2z_ack_mode)
        self.compute_profile = dict(compute_profile or {})

        self.chaotic = ChaoticMap()

        self.D2Z_sessions = {}
        self.D2D_sessions = {}

        self.crp = [None, None]

        # 去同步：每 UAV 仅消耗一次「丢 M3/M4」与一次「拦 D2Z_ACK」（见 desync_attack_first_auth_only）
        self._desync_m3m4_drop_uavs = set()
        self._desync_ack_suppress_uavs = set()
        self._desync_m3m4_anonymous_drop_used = False
        self._desync_ack_anonymous_suppress_used = False
        self._desync_uav_completed_d2z = defaultdict(int)
        # 每 UAV 的 D2Z M1 尝试次数（ACK 抑制会卡住 completed，窗口上限必须基于尝试次数）
        self._desync_uav_attempted_d2z = defaultdict(int)
        # PMAP_ACK: dual-PID transition window state
        # old_pid -> {new_pid, new_crp, challenge, response, session_key, expires_at}
        self._ack_pending_transition = {}

    def _response_delay_s(self) -> float:
        return float(self.compute_profile.get("response_delay_s", 0.0) or 0.0)

    def _send_response_with_compute_delay(self, packet: bytes, dest_addr):
        delay = self._response_delay_s()
        if delay > 0:
            self._safe_schedule(delay, self.SendResponse, packet, dest_addr)
            return
        self.SendResponse(packet, dest_addr)

    def _desync_first_auth_only(self) -> bool:
        return bool(self.attack_model.get("desync_attack_first_auth_only", False))

    def _desync_min_completed_sessions(self) -> int:
        try:
            return max(0, int(self.attack_model.get("desync_attack_min_completed_sessions") or 0))
        except (TypeError, ValueError):
            return 0

    def _desync_max_completed_sessions(self) -> Optional[int]:
        """攻击窗口上限：完成次数超过此值后停止攻击（用于持续攻击+恢复场景）。"""
        try:
            val = self.attack_model.get("desync_attack_max_completed_sessions")
            if val is None:
                return None
            return max(0, int(val))
        except (TypeError, ValueError):
            return None

    def _desync_attack_session_gate_open(self, pid: str) -> bool:
        """在达到去同步门限后才允许进入拦截逻辑。

        当同时配置 min 与 max（且 max>=min）时为「攻击窗口」模式：
        - 下限仍用「已成功 D2Z 次数」completed，保证前 min 次正常完成；
        - 上限用「M1 尝试次数」attempted，避免 ACK 抑制导致 completed 不增、窗口永不关闭。

        仅配置 min、或未配置有效窗口时，沿用仅基于 completed 的旧语义。
        """
        uid = self.uav_db.get(pid, {}).get("uav_id")
        if uid is None:
            return True

        min_c = self._desync_min_completed_sessions()
        max_c = self._desync_max_completed_sessions()
        completed = int(self._desync_uav_completed_d2z.get(uid, 0))

        if max_c is not None and max_c >= min_c:
            attempted = int(self._desync_uav_attempted_d2z.get(uid, 0))
            if completed < min_c:
                return False
            # 第 min_c 次成功对应的当轮 M3/M4 仍不攻击；从下一轮 M1 起 attempted>min_c
            if attempted <= min_c:
                return False
            if attempted > max_c:
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
        if uid is None:
            return
        self._desync_uav_completed_d2z[int(uid)] += 1

    def _consume_m3m4_drop_desync(self, pid: str) -> bool:
        """若本包应按去同步模型丢弃，返回 True。"""
        if not self.attack_model.get("intercept_m3_m4_delivery"):
            return False
        # 攻击窗口检查（支持min/max窗口）
        if not self._desync_attack_session_gate_open(pid):
            return False
        # 单次攻击模式检查
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
        """是否抑制发送 D2Z_ACK（去同步）。"""
        if not self.attack_model.get("intercept_d2z_ack_send"):
            return False
        # 攻击窗口检查（支持min/max窗口）
        if not self._desync_attack_session_gate_open(pid):
            return False
        # 单次攻击模式检查
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

    def _d2z_ctx(self, pid: Optional[str] = None) -> dict:
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

    def _ack_grace_window_s(self) -> float:
        timeout = float(self.attack_model.get("d2z_ack_timeout_s", 5.0) or 5.0)
        attempts = int(self.attack_model.get("max_d2z_attempts", 2) or 2)
        # Cover one timeout-reset cycle plus small buffer.
        return max(5.0, timeout * max(1, attempts) + 2.0)

    def _cleanup_expired_ack_transitions(self) -> None:
        if not self._ack_pending_transition:
            return
        now = ns.Simulator.Now().GetSeconds()
        expired = [old_pid for old_pid, st in self._ack_pending_transition.items() if now >= st.get("expires_at", 0.0)]
        for old_pid in expired:
            st = self._ack_pending_transition.pop(old_pid, None)
            if not st:
                continue
            new_pid = st.get("new_pid")
            # 不再自动删除任何PID，而是等待实际使用时再清理
            # 只有当其中一个PID开始使用时，才删除另一个PID
            # 这样可以避免因窗口过期导致的PID不同步问题
            self.logger.log_warning(
                "PMAP_ACK transition window expired; both PIDs remain active until one is used",
                warning_type="d2z_ack_transition_expired",
                extra={
                    "protocol": self.protocol_name,
                    "analysis_family": self.analysis_family,
                    "flow": "D2Z",
                    "peer_zsp_id": self.zsp_id,
                    "protocol_step": "D2Z_ACK_TRANSITION_EXPIRED",
                    "old_pid": old_pid,
                    "new_pid": new_pid,
                },
            )

    def _stage_ack_transition(
        self,
        old_pid: str,
        new_pid: str,
        challenge: float,
        response: float,
        session_key: int,
    ) -> None:
        """Create dual-PID window for PMAP_ACK; do not hard-cut old PID immediately."""
        if old_pid not in self.uav_db:
            return
        old_info = dict(self.uav_db[old_pid])
        # Keep old PID live for retry path.
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
        self.logger.log_warning(
            "PMAP_ACK dual-PID window opened (old/new both accepted temporarily)",
            warning_type="d2z_ack_dual_pid_window",
            extra={
                "protocol": self.protocol_name,
                "analysis_family": self.analysis_family,
                "flow": "D2Z",
                "peer_zsp_id": self.zsp_id,
                "protocol_step": "D2Z_ACK_DUAL_PID_OPEN",
                "old_pid": old_pid,
                "new_pid": new_pid,
            },
        )

    def _commit_ack_transition_if_confirmed(self, pid: str) -> bool:
        """
        当 M1 的 pid 等于某条待决过渡里的 new_pid 时，视为 UAV 已在带内用新身份续握手，
        提交 old->new（移除旧 PID 记录、清 pending）。注意 new_pid 早已在 `_stage_ack_transition`
        写入 uav_db，故不能再用「pid 不在库中」作为触发条件。
        
        同时处理另一种情况：当 M1 的 pid 是旧PID时，说明UAV仍在使用旧PID，应清理新PID
        """
        # 检查是否是新PID被使用
        for old_pid, st in list(self._ack_pending_transition.items()):
            new_pid = st.get("new_pid")
            if pid == new_pid:
                # 新PID被使用，清理旧PID
                if old_pid in self.uav_db:
                    self.uav_db.pop(old_pid, None)
                if self.enable_blockchain and self.blockchain:
                    try:
                        self.blockchain.update_pid(old_pid, new_pid, st["challenge"], st["response"])
                    except Exception:
                        pass
                self._ack_pending_transition.pop(old_pid, None)
                self.logger.log_warning(
                    "PMAP_ACK transition committed after observing new PID traffic",
                    warning_type="d2z_ack_transition_commit",
                    extra={
                        "protocol": self.protocol_name,
                        "analysis_family": self.analysis_family,
                        "flow": "D2Z",
                        "peer_zsp_id": self.zsp_id,
                        "protocol_step": "D2Z_ACK_DUAL_PID_COMMIT",
                        "old_pid": old_pid,
                        "new_pid": new_pid,
                    },
                )
                return True
        
        # 检查是否是旧PID被使用
        for old_pid, st in list(self._ack_pending_transition.items()):
            new_pid = st.get("new_pid")
            if pid == old_pid:
                # 旧PID被使用，清理新PID
                if new_pid in self.uav_db:
                    self.uav_db.pop(new_pid, None)
                self._ack_pending_transition.pop(old_pid, None)
                self.logger.log_warning(
                    "PMAP_ACK transition cancelled after observing old PID traffic",
                    warning_type="d2z_ack_transition_cancelled",
                    extra={
                        "protocol": self.protocol_name,
                        "analysis_family": self.analysis_family,
                        "flow": "D2Z",
                        "peer_zsp_id": self.zsp_id,
                        "protocol_step": "D2Z_ACK_DUAL_PID_CANCEL",
                        "old_pid": old_pid,
                        "new_pid": new_pid,
                    },
                )
                return True
        return False

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
        # 先尝试提交：`_stage_ack_transition` 已将 new_pid 写入 uav_db，合法 M1 的 pid 即为 new_pid，
        # 必须在清理过期窗口之前提交，否则过期逻辑会删掉 new，而 UAV 已因收到 ACK 切换到 new。
        if self.d2z_ack_mode:
            self._commit_ack_transition_if_confirmed(pid)
        self._cleanup_expired_ack_transitions()

        ctx = self._d2z_ctx(pid)
        # 子会话ID将由log_parser通过关联UAV侧事件来设置
        # 这里暂时使用None，log_parser会在后续处理中关联正确的子会话ID
        subsession_id = None
        
        self.logger.log_message_received(
            "M1",
            wire_len,
            extra={**ctx, "protocol_step": "D2Z_M1_RECV", "subsession_id": subsession_id},
        )

        if pid not in self.uav_db:
            # Unknown PID：须同时记 AUTHENTICATION_FAILED，供 D2ZLogParser / 统计口径将本会话计为认证失败。
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=None,
                extra={
                    **ctx,
                    "protocol_step": "D2Z_M1_FAIL_UNKNOWN_PID",
                    "error_reason": "unknown_pid",
                },
            )
            self.logger.log_error(
                "D2Z M1 rejected: unknown PID not present in this ZSP UAV database",
                error_type="d2z_m1_unknown_pid",
                extra={
                    **ctx,
                    "protocol_step": "D2Z_M1_FAIL_UNKNOWN_PID",
                    "error_reason": "unknown_pid",
                },
            )
            return

        rec = self.uav_db.get(pid) or {}
        uav_id = rec.get("uav_id")
        if uav_id is not None:
            self._desync_uav_attempted_d2z[int(uav_id)] += 1

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
        session.subsession_id = subsession_id  # 存储子会话ID

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

        self._send_response_with_compute_delay(packet, from_addr)
        self.logger.log_message_sent(
            "M2",
            len(packet),
            extra={**self._d2z_ctx(pid), "protocol_step": "D2Z_M2_SEND", "subsession_id": subsession_id},
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
                extra={
                    **ctx,
                    "protocol_step": "D2Z_M3_M4_FAIL_UNKNOWN_PID",
                    "error_reason": "unknown_pid",
                },
            )
            return

        crp = self.uav_db[pid]["crp"]

        m3_size = PMAP.M3.size
        m4_size = PMAP.M4.size
        enc3 = payload[:m3_size]
        enc4 = payload[m3_size:m3_size + m4_size]

        try:
            plain3 = self.chaotic.decrypt_by_crp(enc3, crp)
            plain4 = self.chaotic.decrypt_by_crp(enc4, crp)

            m3 = PMAP.decode(PMAP.M3, plain3)
            m4 = PMAP.decode(PMAP.M4, plain4)
        except Exception as e:
            # 记录认证失败事件，设置错误原因为decrypt_failed
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=self.uav_db[pid].get("uav_id"),
                extra={**ctx, "protocol_step": "D2Z_M3_M4_FAIL_DECRYPT", "error_reason": "decrypt_failed"},
            )
            self.logger.log_error(
                f"D2Z M3/M4 decrypt failed: {e}",
                error_type="d2z_m3_m4_decrypt",
                extra={**ctx, "protocol_step": "D2Z_M3_M4_FAIL_DECRYPT", "error_reason": "decrypt_failed"},
            )
            return

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
        self._send_response_with_compute_delay(ack_packet, session.from_addr)
        self.logger.log_message_sent(
            "D2Z_ACK",
            len(ack_packet),
            extra={**ctx, "protocol_step": "D2Z_ACK_SEND"},
        )
        # PMAP_ACK hard requirement: UAV updates PID only after ACK delivery semantics.
        # Therefore ZSP should keep old PID available during retry window to avoid desync.
        self._stage_ack_transition(
            old_pid=pid,
            new_pid=new_pid,
            challenge=challenge,
            response=response,
            session_key=session_key,
        )
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
            extra={**self._d2z_ctx(new_pid), "protocol_step": "D2Z_SUCCESS", "zsp_session_id": session.zsp_session_id},
        )
        self._note_d2z_success_for_desync_counter(new_pid)

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
            extra={**self._d2z_ctx(new_pid), "protocol_step": "D2Z_SUCCESS", "zsp_session_id": session.zsp_session_id},
        )
        self._note_d2z_success_for_desync_counter(new_pid)

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

        self._send_response_with_compute_delay(packet, from_addr)
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

        self._send_response_with_compute_delay(packet, session.to_addr)
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

        self._send_response_with_compute_delay(packet, session.from_addr)
        seed = self.chaotic.encrypt_by_crp(
                str(session.n2).encode() + str(session.nj).encode(),
                self.crp
            )

        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        new_pid = hash_256(str(self.uav_db[pid]["uav_id"]) + str(response))
        self.UpdateUAVPID(pid, new_pid, challenge, response)

        new_pid = hash_256(str(self.uav_db[pid_i]["uav_id"]) + str(self.crp[1]))
        self.UpdateUAVPID(pid_i, new_pid, self.crp[0], self.crp[1])

