import hashlib
import os
import struct
import uuid
import cppyy
from collections import deque

from ns import ns
from Common.logging_framework import AuthenticationPhase
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


class RLBAUser(ns.Application):
    def __init__(self, node, user_id, gss_id, secret):
        super().__init__()
        self.node = node
        self.user_id = user_id
        self.gss_id = gss_id
        self.secret = secret
        self.pseudo_id = _hash_hex(f"RLBA_USER:{user_id}")
        self.rn1 = None
        self.rn4 = None
        self.ts1 = None
        self.ts5 = None
        self.session_key_ug = None
        self.session_key_ud = None
        self.authenticated = False
        self.socket = None
        self.port = 8080
        self.uav_ids = []  # 存储需要认证的UAV ID列表
        self.current_zsp_id = None  # 记录当前连接的ZSP ID
        self.u2g_auth_session_id = str(uuid.uuid4())  # 用户认证会话ID
        self.logger = None  # 日志记录器，后续会设置
        
        # 容错机制
        self.error_count = 0
        self.max_errors = 50
        
        # 安全调度
        _cap = 262144
        self._event_refs = deque(maxlen=_cap)
        
        print(f"[RLBAUser] User {user_id} initialized with node")

    def generate_auth_request(self, uav_id):
        # 生成用户认证请求
        self.rn1 = _secure_random()
        self.ts1 = _current_timestamp()
        
        # 计算认证值
        user_id_bytes = bytes.fromhex(self.pseudo_id)
        auth_u = _hash_bytes(
            user_id_bytes,
            struct.pack(">d", self.rn1),
            struct.pack(">d", self.ts1),
            struct.pack(">d", uav_id),
            bytes.fromhex(self.secret),
        )
        
        # 构建用户请求消息
        payload = RLBAPlaintext.USER_REQUEST.pack(
            user_id_bytes,
            float(self.rn1),
            float(self.ts1),
            float(uav_id),
            auth_u,
        )
        mac_input = payload + auth_u + bytes.fromhex(self.secret)
        user_pid = _hash_hex(f"RLBA_USER_PID:{self.user_id}")
        packet = RLBAPacket.build(RLBAMessageType.USER_REQUEST, user_pid, payload, mac_input)
        return packet

    def process_gss_response(self, packet_bytes):
        # 处理来自GSS的认证响应
        packet_bytes = bytes(packet_bytes)
        if len(packet_bytes) < RLBAPacket.HEADER_STRUCT.size + 32:
            return False
        msg_type, pid, payload, mac = RLBAPacket.parse(packet_bytes)
        
        if msg_type != RLBAMessageType.GSS_TO_USER:
            return False
        
        gss_id_bytes, user_id_bytes, rn3, rn4, ts4, auth_g, auth_gu = RLBAPlaintext.GSS_TO_USER.unpack(payload)
        
        # 验证用户ID
        if user_id_bytes.hex() != self.pseudo_id:
            return False
        
        # 验证认证值
        expected_auth_gu = _hash_bytes(
            gss_id_bytes,
            struct.pack(">d", rn3),
            struct.pack(">d", ts4),
            bytes.fromhex(self.secret),
        )
        expected_mac = _hash_hex(payload, auth_g, auth_gu, bytes.fromhex(self.secret))
        if auth_gu != expected_auth_gu or mac != expected_mac:
            return False
        
        # 计算会话密钥
        self.rn4 = rn4
        self.session_key_ug = _hash_bytes(
            struct.pack(">d", self.rn1),
            struct.pack(">d", rn4),
            user_id_bytes,
            gss_id_bytes,
            bytes.fromhex(self.secret),
        )
        
        # 验证auth_g
        expected_auth_g = _hash_bytes(self.session_key_ug, user_id_bytes, gss_id_bytes)
        if auth_g != expected_auth_g:
            return False
        
        return True

    def generate_user_confirm(self):
        # 生成用户最终确认消息
        rn5 = _secure_random()
        self.ts5 = _current_timestamp()
        
        # 计算认证值
        user_id_bytes = bytes.fromhex(self.pseudo_id)
        gss_id_bytes = bytes.fromhex(self.gss_id)
        auth_u = _hash_bytes(
            user_id_bytes,
            gss_id_bytes,
            struct.pack(">d", self.rn4),
            struct.pack(">d", rn5),
            struct.pack(">d", self.ts5),
            bytes.fromhex(self.secret),
        )
        
        # 构建用户确认消息
        payload = RLBAPlaintext.USER_CONFIRM.pack(
            user_id_bytes,
            gss_id_bytes,
            float(self.rn4),
            float(rn5),
            float(self.ts5),
            auth_u,
        )
        mac_input = payload + auth_u + bytes.fromhex(self.secret)
        user_pid = _hash_hex(f"RLBA_USER_PID:{self.user_id}")
        packet = RLBAPacket.build(RLBAMessageType.USER_CONFIRM, user_pid, payload, mac_input)
        return packet

    def process_success_message(self, packet_bytes):
        # 处理成功消息
        packet_bytes = bytes(packet_bytes)
        if len(packet_bytes) < RLBAPacket.HEADER_STRUCT.size + 32:
            return False
        msg_type, pid, payload, mac = RLBAPacket.parse(packet_bytes)
        
        if msg_type != RLBAMessageType.SUCCESS:
            return False
        
        gss_id_bytes, user_id_bytes, uav_id_bytes, session_key_ug, session_key_ud = RLBAPlaintext.SUCCESS.unpack(payload)
        
        # 验证用户ID
        if user_id_bytes.hex() != self.pseudo_id:
            return False
        
        # 验证会话密钥
        expected_mac = _hash_hex(payload, session_key_ug, session_key_ud, bytes.fromhex(self.secret))
        if mac != expected_mac:
            return False
        
        # 验证会话密钥是否匹配
        if session_key_ug != self.session_key_ug:
            return False
        
        self.session_key_ud = session_key_ud
        self.authenticated = True
        return True

    def get_session_keys(self):
        # 获取会话密钥
        if not self.authenticated:
            return None, None
        return self.session_key_ug, self.session_key_ud
    
    # =============================
    # 容错核心
    # =============================

    def _safe_execute(self, tag, func, *args):
        try:
            return func(*args)
        except Exception as e:
            self.error_count += 1
            print(f"[RLBAUser] Error in {tag}: {type(e).__name__}: {e}")
            if self.logger:
                self.logger.log_error(
                    f"{type(e).__name__}: {e}",
                    error_type=tag
                )

            if self.error_count > self.max_errors:
                print("[RLBAUser] Too many errors - disabling further execution")
                if self.logger:
                    self.logger.log_error("Too many errors - disabling further execution")

    # =============================
    # 安全调度
    # =============================

    def _safe_schedule(self, delay_sec, func, *args):

        def wrapper():
            self._safe_execute(func.__name__, func, *args)

        event_cb = cppyy.gbl.std.function['void()'](wrapper)

        self._event_refs.append(wrapper)
        self._event_refs.append(event_cb)

        ns.Simulator.Schedule(ns.Seconds(delay_sec), event_cb)
    
    def _u2g_log_extra(self, protocol_step: str) -> dict:
        """生成用户认证日志的额外信息"""
        return {
            "protocol": "RLBA_User",
            "analysis_family": "U2G",
            "auth_session_id": self.u2g_auth_session_id,
            "flow": "U2G",
            "protocol_step": protocol_step,
            "peer_zsp_id": self.current_zsp_id,
            "peer_user_id": self.user_id,
        }
    
    def on_connected_to_zsp(self, zsp_id):
        """连接到ZSP时的回调方法"""
        self.current_zsp_id = zsp_id
        print(f"[RLBAUser] Connected to ZSP {zsp_id}")
        # 连接到ZSP后，自动发起认证请求
        self.u2g_auth_session_id = str(uuid.uuid4())
        # 记录认证初始化事件
        if self.logger:
            self.logger.log_authentication(
                AuthenticationPhase.INITIATED,
                peer_id=zsp_id,
                extra={
                    "protocol": "RLBA_User",
                    "analysis_family": "U2G",
                    "auth_session_id": self.u2g_auth_session_id,
                    "flow": "U2G",
                    "protocol_step": "U2G_INITIATED",
                    "peer_zsp_id": zsp_id,
                    "peer_user_id": self.user_id,
                },
            )
        # 向第一个UAV发起认证请求，但只有当socket初始化后才能发送
        if self.socket:
            self._send_auth_request(0)
        else:
            print(f"[RLBAUser] Socket not initialized yet, will send auth request later")
    
    def StartApplication(self):
        # 启动应用，初始化socket
        def logic():
            print(f"[RLBAUser] Starting user {self.user_id}")
            self.socket = ns.Socket.CreateSocket(self.node, ns.TypeId.LookupByName("ns3::UdpSocket"))
            local_address = ns.InetSocketAddress(ns.Ipv4Address.GetAny(), self.port)
            self.socket.Bind(local_address)
            self.socket.SetRecvCallback(ns.MakeCallback(self._recv_callback))
            
            # 如果已经连接到ZSP，立即发送认证请求
            if self.current_zsp_id:
                print(f"[RLBAUser] Socket initialized, sending auth request to ZSP {self.current_zsp_id}")
                self._send_auth_request(0)
            else:
                # 启动认证流程
                self._safe_schedule(1.0, self._start_authentication)
        
        self._safe_execute("StartApplication", logic)
    
    def StopApplication(self):
        # 停止应用，关闭socket
        print(f"[RLBAUser] Stopping user {self.user_id}")
        if self.socket:
            self.socket.Close()
    
    def _start_authentication(self):
        # 开始认证流程，尝试连接UAV 0
        # 这里简化处理，只尝试UAV ID 0
        self.uav_ids.append(0)
        self._send_auth_request(0)
    
    def _send_auth_request(self, uav_id):
        # 发送认证请求
        packet = self.generate_auth_request(uav_id)
        if packet:
            gss_address = ns.InetSocketAddress(ns.Ipv4Address("10.1.1.2"), 8080)  # 假设GSS的IP是10.1.1.2
            self.socket.SendTo(packet, 0, gss_address)
            print(f"[RLBAUser] Sent auth request for UAV {uav_id} to GSS")
            # 记录消息发送事件
            if self.logger:
                self.logger.log_message_sent(
                    "USER_REQUEST", 
                    len(packet), 
                    extra=self._u2g_log_extra("RLBA_USER_INIT")
                )
                self.logger.log_authentication(
                    AuthenticationPhase.INITIATED,
                    peer_id=self.current_zsp_id,
                    extra={
                        "protocol": "RLBA_User",
                        "analysis_family": "U2G",
                        "auth_session_id": self.u2g_auth_session_id,
                        "flow": "U2G",
                        "protocol_step": "RLBA_USER_INIT",
                        "peer_zsp_id": self.current_zsp_id,
                        "peer_user_id": self.user_id,
                        "target_uav_id": uav_id,
                    },
                )
    
    def _recv_callback(self, socket):
        # 接收消息的回调函数
        while socket.GetRxAvailable() > 0:
            packet_size = socket.GetRxAvailable()
            packet = ns.Packet()
            address = ns.InetSocketAddress()
            packet_size = socket.RecvFrom(packet, address)
            
            packet_bytes = b""
            if packet_size > 0:
                # 使用更安全的方式获取数据包内容
                buffer = bytearray(packet_size)
                packet.CopyData(buffer, packet_size)
                packet_bytes = bytes(buffer)
                self._process_packet(packet_bytes)
    
    def _process_packet(self, packet_bytes):
        # 处理接收到的数据包
        try:
            if len(packet_bytes) < RLBAPacket.HEADER_STRUCT.size + 32:
                return
            
            msg_type, pid, payload, mac = RLBAPacket.parse(packet_bytes)
            
            if msg_type == RLBAMessageType.GSS_TO_USER:
                # 处理GSS的响应
                print(f"[RLBAUser] Received GSS_TO_USER message")
                # 记录消息接收事件
                if self.logger:
                    self.logger.log_message_received(
                        "GSS_TO_USER", 
                        len(packet_bytes), 
                        extra=self._u2g_log_extra("RLBA_GSS_RESPONSE")
                    )
                if self.process_gss_response(packet_bytes):
                    # 生成用户确认
                    confirm_packet = self.generate_user_confirm()
                    if confirm_packet:
                        gss_address = ns.InetSocketAddress(ns.Ipv4Address("10.1.1.2"), 8080)
                        self.socket.SendTo(confirm_packet, 0, gss_address)
                        print(f"[RLBAUser] Sent user confirm")
                        # 记录消息发送事件
                        if self.logger:
                            self.logger.log_message_sent(
                                "USER_CONFIRM", 
                                len(confirm_packet), 
                                extra=self._u2g_log_extra("RLBA_USER_CONFIRM")
                            )
            elif msg_type == RLBAMessageType.SUCCESS:
                # 处理成功消息
                print(f"[RLBAUser] Received SUCCESS message")
                # 记录消息接收事件
                if self.logger:
                    self.logger.log_message_received(
                        "SUCCESS", 
                        len(packet_bytes), 
                        extra=self._u2g_log_extra("U2G_ACK_RECV")
                    )
                if self.process_success_message(packet_bytes):
                    print(f"[RLBAUser] Authentication successful")
                    # 记录认证成功事件
                    if self.logger:
                        self.logger.log_session_established(
                            session_id=self.u2g_auth_session_id,
                            session_key_hash=self.session_key_ug.hex()[:16],
                            peer_id=self.current_zsp_id,
                            extra=self._u2g_log_extra("RLBA_SUCCESS")
                        )
                        self.logger.log_authentication(
                            AuthenticationPhase.SUCCESS,
                            success=True,
                            peer_id=self.current_zsp_id,
                            extra=self._u2g_log_extra("U2G_SUCCESS")
                        )
        except Exception as e:
            print(f"[RLBAUser] Error processing packet: {e}")