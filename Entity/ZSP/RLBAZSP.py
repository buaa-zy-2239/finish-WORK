import hashlib
import os
import struct
from collections import defaultdict
from typing import Optional
from Common.logging_framework import AuthenticationPhase
from Entity.ZSP.BaseZSP import BaseZSP
from Protocol.RLBA.MsgType import RLBAMessageType
from Protocol.RLBA.Packet import RLBAPacket
from Protocol.RLBA.Plaintext import RLBAPlaintext
from BlockChain.Blockchain import Web3BlockchainAdapter


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


class RLBAZSP(BaseZSP):
    def __init__(
        self,
        node,
        zsp_id,
        blockchain=None,
        enable_blockchain=True,
        blockchain_config=None,
        attack_model=None,
        **_kwargs,
    ):
        super().__init__(
            node,
            zsp_id,
            blockchain=blockchain,
            enable_blockchain=enable_blockchain,
            protocol_name="RLBA_UAV",
            analysis_family="D2Z",
        )
        self.attack_model = attack_model if attack_model is not None else {}
        self.sessions = {}
        self.drone_pseudo_id = _hash_hex(f"RLBA_DRONE:{zsp_id}")
        self._desync_ack_suppress_uavs = set()
        self._desync_ack_anonymous_suppress_used = False
        self._desync_m3_drop_uavs = set()
        self._desync_m3_drop_anonymous_used = False
        self._desync_uav_completed_d2z = defaultdict(int)
        self._desync_uav_attempted_d2z = defaultdict(int)
        # 区块链相关
        self.blockchain = blockchain
        if not self.blockchain and blockchain_config:
            try:
                self.blockchain = Web3BlockchainAdapter(**blockchain_config)
            except Exception as e:
                self.logger.log_warning(f"Blockchain initialization failed: {e}")
        # 用户会话管理
        self._user_sessions = {}
        # 服务端ID
        self.id = _hash_hex(f"RLBA_GSS:{zsp_id}")

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
        """去同步门限：与 PMAPZSP 一致，攻击窗口模式下上限基于 M1 尝试次数。"""
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

    def _should_suppress_final_downlink_desync(self, pid: str) -> bool:
        """与 PMAP_ACK 的 `_should_suppress_d2z_ack_desync` 共用 `intercept_d2z_ack_send` 语义。"""
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

    def _should_drop_m3_delivery_desync(self, pid: str) -> bool:
        if not self.attack_model.get("intercept_m3_m4_delivery"):
            return False
        # 攻击窗口检查（支持min/max窗口）
        if not self._desync_attack_session_gate_open(pid):
            return False
        # 单次攻击模式检查
        if self._desync_first_auth_only():
            uid = self.uav_db.get(pid, {}).get("uav_id")
            if uid is None:
                if self._desync_m3_drop_anonymous_used:
                    return False
                self._desync_m3_drop_anonymous_used = True
                return True
            if uid in self._desync_m3_drop_uavs:
                return False
            self._desync_m3_drop_uavs.add(uid)
        return True

    def ProcessRequest(self, buf, from_addr):
        packet_bytes = bytes(buf)
        if len(packet_bytes) < RLBAPacket.HEADER_STRUCT.size + 32:
            return
        msg_type, pid, payload, mac = RLBAPacket.parse(packet_bytes)
        if msg_type == RLBAMessageType.USER_REQUEST:
            # 处理用户的认证请求
            self._handle_user_request(payload, mac, from_addr, len(packet_bytes))
        elif msg_type == RLBAMessageType.UAV_TO_GSS:
            # 处理UAV的认证响应
            self._handle_uav_response(pid, payload, mac, from_addr, len(packet_bytes))
        elif msg_type == RLBAMessageType.USER_CONFIRM:
            # 处理用户的最终确认
            self._handle_user_confirm(payload, mac, from_addr, len(packet_bytes))
        elif msg_type == RLBAMessageType.M1:
            # 处理UAV的认证请求（兼容PMAP格式）
            self._handle_m1(pid, payload, mac, from_addr, len(packet_bytes))
        elif msg_type == RLBAMessageType.M3:
            # 处理UAV的认证响应（兼容PMAP格式）
            self._handle_m3(pid, payload, mac, from_addr, len(packet_bytes))

    def _handle_m1(self, pid, payload, mac, from_addr, wire_len):
        record = self.uav_db.get(pid)
        if record:
            uid = record.get("uav_id")
            if uid is not None:
                self._desync_uav_attempted_d2z[int(uid)] += 1

        ctx = self._d2z_ctx(pid)
        # 验证UAV的PID是否在区块链中有效
        if self.blockchain:
            if not self.blockchain.is_valid_uav(pid):
                self.logger.log_authentication(
                    AuthenticationPhase.FAILED,
                    success=False,
                    peer_id=None,
                    extra={**ctx, "protocol_step": "RLBA_BLOCKCHAIN_INVALID", "error_reason": "blockchain_invalid_pid"},
                )
                # 记录认证失败到区块链
                self.blockchain.record_auth_event(pid, False)
                return
        
        if not record:
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=None,
                extra={**ctx, "protocol_step": "RLBA_UNKNOWN_PID", "error_reason": "unknown_pid"},
            )
            # 记录认证失败到区块链
            if self.blockchain:
                self.blockchain.record_auth_event(pid, False)
            return
        pseudo_u_bytes, rn1, ts1, zsp_id, auth_u = RLBAPlaintext.M1.unpack(payload)
        secret = bytes.fromhex(record["secret"])
        
        # 生成PUF挑战和响应（这里假设UAV使用相同的挑战生成方法）
        puf_challenge = _secure_random()
        # 模拟PUF响应生成
        puf_response = _hash_hex(f"PUF:{record.get('uav_id')}:{puf_challenge}")
        puf_response_float = float(struct.unpack('>d', bytes.fromhex(puf_response[:16]))[0])
        
        expected_auth = _hash_bytes(
            pseudo_u_bytes,
            struct.pack(">d", rn1),
            struct.pack(">d", ts1),
            struct.pack(">d", puf_challenge),
            struct.pack(">d", puf_response_float),
            secret,
        )
        expected_mac = _hash_hex(payload, expected_auth, secret)
        if (
            pseudo_u_bytes.hex() != record["pseudo_id"]
            or int(zsp_id) != self.zsp_id
            or auth_u != expected_auth
            or mac != expected_mac
        ):
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=record.get("uav_id"),
                extra={**ctx, "protocol_step": "RLBA_INIT_VERIFY_FAIL", "error_reason": "invalid_m1"},
            )
            # 记录认证失败到区块链
            if self.blockchain:
                self.blockchain.record_auth_event(pid, False)
            return

        # 使用安全随机数
        rn2 = _secure_random()
        # 使用真实时间戳
        ts2 = _current_timestamp()
        self.sessions[pid] = {
            "from_addr": from_addr,
            "rn1": rn1,
            "rn2": rn2,
            "pseudo_u": pseudo_u_bytes,
            "pseudo_d": bytes.fromhex(self.drone_pseudo_id),
            "secret": secret,
            "puf_challenge": puf_challenge,
            "puf_response": puf_response_float,
        }
        self.logger.log_message_received("M1", wire_len, extra={**ctx, "protocol_step": "RLBA_INIT"})
        auth_d = _hash_bytes(
            pseudo_u_bytes,
            bytes.fromhex(self.drone_pseudo_id),
            struct.pack(">d", rn1),
            struct.pack(">d", rn2),
            struct.pack(">d", ts2),
            struct.pack(">d", puf_challenge),
            struct.pack(">d", puf_response_float),
            secret,
        )
        m2_payload = RLBAPlaintext.M2.pack(
            pseudo_u_bytes,
            bytes.fromhex(self.drone_pseudo_id),
            float(rn1),
            float(rn2),
            float(ts2),
            auth_d,
        )
        m2_mac_input = m2_payload + auth_d + secret
        packet = RLBAPacket.build(RLBAMessageType.M2, pid, m2_payload, m2_mac_input)
        self.logger.log_message_sent("M2", len(packet), extra={**ctx, "protocol_step": "RLBA_CHALLENGE"})
        self.SendResponse(packet, from_addr)

    def _handle_m3(self, pid, payload, mac, from_addr, wire_len):
        ctx = self._d2z_ctx(pid)
        record = self.uav_db.get(pid)
        session = self.sessions.get(pid)
        if not record or not session:
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=record.get("uav_id") if record else None,
                extra={**ctx, "protocol_step": "RLBA_RESPONSE_ORPHAN", "error_reason": "orphan_m3"},
            )
            # 记录认证失败到区块链
            if self.blockchain:
                self.blockchain.record_auth_event(pid, False)
            return
        pseudo_u_bytes, pseudo_d_bytes, rn2, rn3, ts3, auth_ud, auth_gss = RLBAPlaintext.M3.unpack(payload)
        session_key = _hash_bytes(
            struct.pack(">d", session["rn1"]),
            struct.pack(">d", session["rn2"]),
            struct.pack(">d", rn3),
            pseudo_u_bytes,
            pseudo_d_bytes,
        )
        expected_auth_ud = _hash_bytes(session_key, pseudo_u_bytes, pseudo_d_bytes)
        expected_auth_gss = _hash_bytes(
            pseudo_d_bytes,
            struct.pack(">d", session["rn1"]),
            struct.pack(">d", ts3),
            session["secret"],
        )
        expected_mac = _hash_hex(payload, expected_auth_ud, expected_auth_gss, session["secret"])
        if (
            pseudo_u_bytes != session["pseudo_u"]
            or pseudo_d_bytes != session["pseudo_d"]
            or rn2 != session["rn2"]
            or auth_ud != expected_auth_ud
            or auth_gss != expected_auth_gss
            or mac != expected_mac
        ):
            self.logger.log_authentication(
                AuthenticationPhase.FAILED,
                success=False,
                peer_id=record.get("uav_id"),
                extra={**ctx, "protocol_step": "RLBA_RESPONSE_VERIFY_FAIL", "error_reason": "invalid_m3"},
            )
            # 记录认证失败到区块链
            if self.blockchain:
                self.blockchain.record_auth_event(pid, False)
            return

        self.logger.log_message_received("M3", wire_len, extra={**ctx, "protocol_step": "RLBA_RESPONSE"})
        if self._should_drop_m3_delivery_desync(pid):
            self.logger.log_warning(
                "attack: M3 dropped at ZSP (desync semantic alignment)",
                warning_type="attack_desync",
                extra={**ctx, "protocol_step": "M3_M4_DROPPED"},
            )
            # 记录认证失败到区块链
            if self.blockchain:
                self.blockchain.record_auth_event(pid, False)
            self.sessions.pop(pid, None)
            return
        session_key_hash = session_key.hex()

        if self._should_suppress_final_downlink_desync(pid):
            self.logger.log_warning(
                "attack: D2Z ACK not sent after M3/M4 (session redundancy test)",
                warning_type="attack_desync",
                extra={**ctx, "protocol_step": "D2Z_ACK_SUPPRESSED"},
            )
            # 记录认证失败到区块链
            if self.blockchain:
                self.blockchain.record_auth_event(pid, False)
            self.sessions.pop(pid, None)
            return

        success_payload = RLBAPlaintext.SUCCESS.pack(
            pseudo_u_bytes,
            pseudo_d_bytes,
            session_key,
        )
        success_packet = RLBAPacket.build(
            RLBAMessageType.SUCCESS,
            pid,
            success_payload,
            success_payload + session_key + session["secret"],
        )
        self.SendResponse(success_packet, from_addr)
        self.logger.log_message_sent(
            "RLBA_SUCCESS",
            len(success_packet),
            extra={**ctx, "protocol_step": "D2Z_ACK_SEND"},
        )
        # 记录认证成功到区块链
        if self.blockchain:
            self.blockchain.record_auth_event(pid, True)
        self.logger.log_authentication(
            AuthenticationPhase.SUCCESS,
            peer_id=record.get("uav_id"),
            extra={**ctx, "protocol_step": "RLBA_SUCCESS", "session_key_hash": session_key_hash},
        )
        uid = record.get("uav_id")
        if uid is not None:
            self._desync_uav_completed_d2z[int(uid)] += 1
        self.logger.log_session_established(
            session_id=f"rlba-{record.get('uav_id')}-{self.zsp_id}",
            session_key_hash=session_key_hash,
            peer_id=record.get("uav_id"),
            extra={**ctx, "protocol_step": "RLBA_SUCCESS"},
        )
        self.sessions.pop(pid, None)

    def _handle_user_request(self, payload, mac, from_addr, wire_len):
        # 处理用户的认证请求
        user_id_bytes, rn1, ts1, uav_id, auth_u = RLBAPlaintext.USER_REQUEST.unpack(payload)
        user_id = user_id_bytes.hex()
        
        # 验证用户的合法性
        if not self._verify_user(user_id):
            self.logger.log_warning(
                f"Invalid user: {user_id}",
                warning_type="rlba_invalid_user",
                extra={"protocol": "RLBA_ZSP"},
            )
            return
        
        # 查找UAV
        uav = self._find_uav_by_id(uav_id)
        if uav is None:
            self.logger.log_warning(
                f"Unknown UAV: {uav_id}",
                warning_type="rlba_unknown_uav",
                extra={"protocol": "RLBA_ZSP"},
            )
            return
        
        # 验证用户认证值
        secret = bytes.fromhex(uav["secret"])
        expected_auth = _hash_bytes(
            user_id_bytes,
            struct.pack(">d", rn1),
            struct.pack(">d", ts1),
            struct.pack(">d", uav_id),
            secret,
        )
        expected_mac = _hash_hex(payload, expected_auth, secret)
        if auth_u != expected_auth or mac != expected_mac:
            # 认证失败，记录到区块链
            if self.blockchain:
                self.blockchain.record_auth_event(uav["pid"], False)
            return
        
        # 生成安全随机数
        rn2 = _secure_random()
        # 使用真实时间戳
        ts2 = _current_timestamp()
        
        # 检查PID是否在区块链中有效
        if self.blockchain:
            if not self.blockchain.is_valid_uav(uav["pid"]):
                self.logger.log_authentication(
                    AuthenticationPhase.FAILED,
                    success=False,
                    peer_id=None,
                    extra={"protocol": "RLBA_ZSP", "protocol_step": "RLBA_BLOCKCHAIN_INVALID", "error_reason": "blockchain_invalid_pid"},
                )
                # 记录认证失败到区块链
                self.blockchain.record_auth_event(uav["pid"], False)
                return
        
        # 计算认证值
        auth_g = _hash_bytes(
            bytes.fromhex(self.id),
            user_id_bytes,
            struct.pack(">d", rn1),
            struct.pack(">d", rn2),
            struct.pack(">d", ts2),
            secret,
        )
        
        # 构建GSS到UAV的认证请求消息
        gss_to_uav_payload = RLBAPlaintext.GSS_TO_UAV.pack(
            bytes.fromhex(self.id),
            user_id_bytes,
            float(rn1),
            float(rn2),
            float(ts2),
            auth_g,
        )
        gss_to_uav_mac_input = gss_to_uav_payload + auth_g + secret
        packet = RLBAPacket.build(RLBAMessageType.GSS_TO_UAV, uav["pid"], gss_to_uav_payload, gss_to_uav_mac_input)
        self.SendResponse(packet, from_addr)
        
        # 存储用户会话信息
        self._user_sessions[user_id] = {
            "rn1": rn1,
            "rn2": rn2,
            "ts2": ts2,
            "uav_id": uav_id,
            "user_id": user_id,
            "uav": uav,
            "from_addr": from_addr
        }

    def _handle_uav_response(self, pid, payload, mac, from_addr, wire_len):
        # 处理UAV的认证响应
        uav_id_bytes, gss_id_bytes, user_id_bytes, rn2, rn3, ts3, auth_d, auth_gss = RLBAPlaintext.UAV_TO_GSS.unpack(payload)
        user_id = user_id_bytes.hex()
        
        # 查找用户会话
        user_session = self._user_sessions.get(user_id)
        if not user_session or rn2 != user_session["rn2"]:
            # 认证失败，记录到区块链
            if self.blockchain:
                self.blockchain.record_auth_event(pid, False)
            return
        
        uav = user_session["uav"]
        secret = bytes.fromhex(uav["secret"])
        
        # 验证UAV认证值
        expected_auth_d = _hash_bytes(
            struct.pack(">d", user_session["rn1"]),
            struct.pack(">d", rn2),
            struct.pack(">d", rn3),
            user_id_bytes,
            gss_id_bytes,
            secret,
        )
        expected_auth_gss = _hash_bytes(
            gss_id_bytes,
            struct.pack(">d", user_session["rn1"]),
            struct.pack(">d", ts3),
            secret,
        )
        expected_mac = _hash_hex(
            payload, expected_auth_d, expected_auth_gss, secret
        )
        if auth_d != expected_auth_d or auth_gss != expected_auth_gss or mac != expected_mac:
            # 认证失败，记录到区块链
            if self.blockchain:
                self.blockchain.record_auth_event(pid, False)
            return
        
        # 生成安全随机数
        rn4 = _secure_random()
        # 使用真实时间戳
        ts4 = _current_timestamp()
        
        # 计算会话密钥
        session_key_ud = _hash_bytes(
            struct.pack(">d", user_session["rn1"]),
            struct.pack(">d", rn2),
            struct.pack(">d", rn3),
            user_id_bytes,
            gss_id_bytes,
            secret,
        )
        session_key_ug = _hash_bytes(
            struct.pack(">d", user_session["rn1"]),
            struct.pack(">d", rn4),
            user_id_bytes,
            gss_id_bytes,
            secret,
        )
        
        # 计算认证值
        auth_g = _hash_bytes(session_key_ug, user_id_bytes, gss_id_bytes)
        auth_gu = _hash_bytes(
            gss_id_bytes,
            struct.pack(">d", rn3),
            struct.pack(">d", ts4),
            secret,
        )
        
        # 构建GSS到用户的认证响应消息
        gss_to_user_payload = RLBAPlaintext.GSS_TO_USER.pack(
            gss_id_bytes,
            user_id_bytes,
            float(rn3),
            float(rn4),
            float(ts4),
            auth_g,
            auth_gu,
        )
        gss_to_user_mac_input = gss_to_user_payload + auth_g + auth_gu + secret
        # 这里假设用户也有一个PID，实际实现中需要根据用户的PID发送
        user_pid = _hash_hex(f"RLBA_USER_PID:{user_id}")
        packet = RLBAPacket.build(RLBAMessageType.GSS_TO_USER, user_pid, gss_to_user_payload, gss_to_user_mac_input)
        self.SendResponse(packet, user_session["from_addr"])
        
        # 更新用户会话信息
        user_session["rn3"] = rn3
        user_session["rn4"] = rn4
        user_session["ts4"] = ts4
        user_session["session_key_ud"] = session_key_ud
        user_session["session_key_ug"] = session_key_ug

    def _handle_user_confirm(self, payload, mac, from_addr, wire_len):
        # 处理用户的最终确认
        user_id_bytes, gss_id_bytes, rn4, rn5, ts5, auth_u = RLBAPlaintext.USER_CONFIRM.unpack(payload)
        user_id = user_id_bytes.hex()
        
        # 查找用户会话
        user_session = self._user_sessions.get(user_id)
        if not user_session or rn4 != user_session["rn4"]:
            return
        
        uav = user_session["uav"]
        secret = bytes.fromhex(uav["secret"])
        
        # 验证用户确认认证值
        expected_auth = _hash_bytes(
            user_id_bytes,
            gss_id_bytes,
            struct.pack(">d", rn4),
            struct.pack(">d", rn5),
            struct.pack(">d", ts5),
            secret,
        )
        expected_mac = _hash_hex(payload, expected_auth, secret)
        if auth_u != expected_auth or mac != expected_mac:
            # 认证失败，记录到区块链
            if self.blockchain:
                self.blockchain.record_auth_event(uav["pid"], False)
            return
        
        # 构建成功消息
        success_payload = RLBAPlaintext.SUCCESS.pack(
            gss_id_bytes,
            user_id_bytes,
            bytes.fromhex(uav["pseudo_id"]),
            user_session["session_key_ug"],
            user_session["session_key_ud"],
        )
        success_mac_input = success_payload + user_session["session_key_ug"] + user_session["session_key_ud"] + secret
        packet = RLBAPacket.build(RLBAMessageType.SUCCESS, uav["pid"], success_payload, success_mac_input)
        self.SendResponse(packet, user_session["from_addr"])
        
        # 认证成功，记录到区块链
        if self.blockchain:
            self.blockchain.record_auth_event(uav["pid"], True)
        
        # 清理用户会话
        del self._user_sessions[user_id]

    def _verify_user(self, user_id):
        # 验证用户的合法性，实际实现中应该从数据库或区块链中验证
        # 这里简单返回True，模拟用户验证成功
        return True

    def _find_uav_by_id(self, uav_id):
        # 根据UAV ID查找UAV
        for pid, record in self.uav_db.items():
            if record.get("uav_id") == uav_id:
                return record
        return None
