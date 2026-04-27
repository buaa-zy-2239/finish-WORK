from ns import ns
import cppyy
import abc
from collections import deque
import random
import os
import time
import json
from Common.logging_framework import (
    ZSPLogger, DatabaseOperation, AuthenticationPhase, IdentifierOperation
)
from Common.crp_chain_codec import canonicalize_crp_pair
from Entity.UAV.BaseUAV import BaseUAV
from Common.desync_experiment_hooks import emit_desync_pid_transition


class BaseZSP(ns.Application):

    def __init__(
        self,
        node,
        zsp_id,
        blockchain=None,
        enable_blockchain=True,
        protocol_name="GENERIC",
        analysis_family="D2Z",
    ):

        super().__init__()

        BaseUAV.ZSP_REGISTRY.append(self)

        self.node = node
        self.zsp_id = zsp_id
        self.protocol_name = protocol_name
        self.analysis_family = analysis_family

        self.enable_blockchain = enable_blockchain
        self.blockchain = blockchain

        # UAV DB
        self.uav_db = {}

        # Socket
        self.m_socket = ns.Socket.CreateSocket(
            self.node,
            ns.TypeId.LookupByName("ns3::UdpSocketFactory")
        )
        self.m_socket.SetAllowBroadcast(True)

        # 有界保留，避免长时间仿真 + 多机时调度包装器无限堆积（见 BaseUAV 同字段说明）
        _cap = 262144
        self._poll_refs = deque(maxlen=_cap)
        self._poll_interval = ns.MilliSeconds(100)

        # Blockchain poll
        self._bc_refs = deque(maxlen=_cap)
        self._bc_poll_interval = ns.Seconds(1)
        self._event_refs = deque(maxlen=_cap)

        if blockchain:
            self.last_event_block = blockchain.w3.eth.block_number - 1
        else:
            self.last_event_block = 0

        # 容错
        self.error_count = 0
        self.max_errors = 50
        self._downlink_ge_bad_state = False

        self.logger = ZSPLogger(zsp_id)
    # =============================
    # 容错核心
    # =============================

    def _safe_execute(self, tag, func, *args):
        try:
            return func(*args)
        except Exception as e:
            self.error_count += 1
            self.logger.log_error(
                f"{type(e).__name__}: {e}",
                error_type=tag
            )

            if self.error_count > self.max_errors:
                self.logger.log_error("Too many errors → degraded mode")

    # =============================
    # Mobility
    # =============================

    def _install_mobility(self):

        def logic():

            mobility = self.node.GetObject[ns.MobilityModel]()
            if mobility:
                return

            helper = ns.MobilityHelper()
            helper.SetMobilityModel("ns3::ConstantPositionMobilityModel")

            container = ns.NodeContainer()
            container.Add(self.node)
            helper.Install(container)

            mobility = self.node.GetObject[ns.MobilityModel]()
            mobility.SetPosition(ns.Vector(self.zsp_id * 500, 0, 100))

        self._safe_execute("install_mobility", logic)

    # =============================
    # Address
    # =============================

    def GetAddress(self):

        try:
            ipv4 = self.node.GetObject[ns.Ipv4]()
            addr = ipv4.GetAddress(1, 0)
            return addr.GetLocal()
        except Exception as e:
            self.logger.log_error(f"GetAddress error: {e}", error_type="GetAddress")
            return ns.Ipv4Address("0.0.0.0")

    # =============================
    # 生命周期
    # =============================

    def StartApplication(self):

        def logic():

            local_address = ns.InetSocketAddress(
                ns.Ipv4Address.GetAny(),
                9999
            )

            self.m_socket.Bind(local_address.ConvertTo())

            self.logger.log_debug("ZSP service started")

            self._install_recv_callback()

            if self.enable_blockchain and self.blockchain:
                self._schedule_blockchain_poll()

        self._safe_execute("StartApplication", logic)

    def StopApplication(self):

        try:
            if self.m_socket:
                self.m_socket.Close()
        except Exception as e:
            self.logger.log_error(f"Stop error: {e}", error_type="StopApplication")

    # =============================
    # Socket Receive Callback
    # =============================

    def _install_recv_callback(self):

        def on_recv(sock):
            self._safe_execute("recv_callback", self._drain_socket_packets, sock)

        wrapper = cppyy.gbl.std.function['void(ns3::Ptr<ns3::Socket>)'](on_recv)
        self._poll_refs.append(on_recv)
        self._poll_refs.append(wrapper)
        self.m_socket.SetRecvCallback(wrapper)

    def _drain_socket_packets(self, sock=None):
        sock_obj = sock if sock is not None else self.m_socket
        while True:
            try:
                if sock_obj.GetRxAvailable() <= 0:
                    break
            except Exception as e:
                self.logger.log_error(f"Socket state error: {e}", error_type="socket_state")
                break

            try:
                from_addr = ns.Address()
                packet = sock_obj.RecvFrom(from_addr)
            except Exception as e:
                self.logger.log_error(f"Recv error: {e}", error_type="socket_recv")
                break

            if not packet or packet.GetSize() == 0:
                break

            try:
                size = packet.GetSize()
                buf = bytearray(size)
                packet.CopyData(buf, size)
                self.ProcessRequest(buf, from_addr)
            except Exception as e:
                self.logger.log_error(f"Packet process error: {e}", error_type="packet_processing")

    # =============================
    # Blockchain Poll
    # =============================

    def _schedule_blockchain_poll(self):

        def wrapper():
            self._safe_execute("blockchain_poll", self._poll_blockchain_events)

        cb = cppyy.gbl.std.function['void()'](wrapper)

        self._bc_refs.append(wrapper)
        self._bc_refs.append(cb)

        ns.Simulator.Schedule(self._bc_poll_interval, cb)

    def _poll_blockchain_events(self):

        latest = self.blockchain.w3.eth.block_number

        events = self.blockchain.get_pid_update_events(
            self.last_event_block + 1,
            latest
        )

        self.last_event_block = latest

        for e in events:

            try:
                old_pid = e["old_pid"]
                new_pid = e["new_pid"]

                challenge, response = canonicalize_crp_pair(
                    float(e["challenge"]), float(e["response"])
                )

                if old_pid not in self.uav_db:
                    if new_pid in self.uav_db:
                        self.uav_db[new_pid]["crp"] = [challenge, response]
                    continue

                old_crp = self.uav_db[old_pid].get("crp", ["?", "?"])

                self.logger.log_pid_rotation(
                    old_pid, new_pid,
                    old_crp=old_crp,
                    new_crp=[challenge, response],
                )

                self._handle_pid_update(old_pid, new_pid)

                self.uav_db[new_pid]["crp"] = [challenge, response]

            except Exception as e:
                self.logger.log_error(f"Event processing error: {e}", error_type="blockchain_event")

        self._schedule_blockchain_poll()

    def _safe_schedule(self, delay_sec, func, *args):

        def wrapper():
            self._safe_execute(func.__name__, func, *args)

        event_cb = cppyy.gbl.std.function['void()'](wrapper)

        self._event_refs.append(wrapper)
        self._event_refs.append(event_cb)

        ns.Simulator.Schedule(ns.Seconds(delay_sec), event_cb)

    # =============================
    # PID 同步
    # =============================

    def _handle_pid_update(self, old_pid, new_pid):

        try:
            if old_pid in self.uav_db:

                info = self.uav_db.pop(old_pid)
                info["pid"] = new_pid

                self.uav_db[new_pid] = info
                emit_desync_pid_transition(
                    self,
                    "zsp",
                    "_handle_pid_update",
                    old_pid=old_pid,
                    new_pid=new_pid,
                )

            else:
                return

            self.logger.log_uav_db_operation(
                    DatabaseOperation.UPDATED,
                    uav_pid=new_pid
                )

        except Exception as e:
            self.logger.log_error(f"PID update error: {e}", error_type="pid_update")

    # =============================
    # UAV 注册
    # =============================

    def RegisterUAV(self, pid, reg_info):

        def logic():

            if pid not in self.uav_db:
                self.uav_db[pid] = reg_info
                # 只有当enable_blockchain为True且blockchain不为None时，才使用区块链
                if self.enable_blockchain and self.blockchain:
                    if hasattr(self.blockchain, 'is_valid_uav') and hasattr(self.blockchain, 'register_uav'):
                        if not self.blockchain.is_valid_uav(pid):
                            self.blockchain.register_uav(pid)
            self.logger.log_uav_db_operation(
                    DatabaseOperation.REGISTERED,
                    uav_pid=pid,
                    uav_id=reg_info.get("uav_id")
                )
        self._safe_execute("RegisterUAV", logic)

    # =============================
    # PID 更新
    # =============================

    def UpdateUAVPID(self, old_pid, new_pid, new_challenge, new_response):

        def logic():
            nc, nr = canonicalize_crp_pair(float(new_challenge), float(new_response))

            mutated = False
            if old_pid in self.uav_db:

                info = self.uav_db.pop(old_pid)
                info["pid"] = new_pid

                self.uav_db[new_pid] = info
                self.uav_db[new_pid]["crp"] = [nc, nr]
                mutated = True

            self.logger.log_pid_rotation(
                    old_pid, new_pid,
                    new_crp=[nc, nr],
                )

            if self.enable_blockchain and self.blockchain:
                self.blockchain.update_pid(
                    old_pid, new_pid,
                    nc, nr,
                )

            if mutated:
                emit_desync_pid_transition(
                    self,
                    "zsp",
                    "UpdateUAVPID",
                    old_pid=old_pid,
                    new_pid=new_pid,
                )

        self._safe_execute("UpdateUAVPID", logic)

    # =============================
    # Send Packet
    # =============================

    def SendResponse(self, data_bytes, dest_addr):

        def logic():
            attack_model = getattr(self, "attack_model", {}) or {}
            downlink_loss_rate = float(attack_model.get("downlink_loss_rate", 0.0) or 0.0)
            burst_loss_rate = self._downlink_burst_loss_rate(attack_model)
            combined_loss_rate = 1.0 - (1.0 - downlink_loss_rate) * (1.0 - burst_loss_rate)
            if combined_loss_rate > 0.0 and random.random() < combined_loss_rate:
                self.logger.log_warning(
                    "Probabilistic downlink drop injected",
                    warning_type="downlink_loss_injected",
                    extra={
                        "loss_rate": combined_loss_rate,
                        "downlink_loss_rate": downlink_loss_rate,
                        "burst_loss_rate": burst_loss_rate,
                        "peer_zsp_id": self.zsp_id,
                    },
                )
                return

            size = len(data_bytes)

            cpp_buffer = cppyy.gbl.std.vector['uint8_t'](size)

            for i in range(size):
                cpp_buffer[i] = data_bytes[i]

            packet = ns.Packet(cpp_buffer.data(), size)

            self.m_socket.SendTo(packet, 0, dest_addr)

        self._safe_execute("SendResponse", logic)

    def _downlink_burst_loss_rate(self, attack_model: dict) -> float:
        model = attack_model.get("downlink_burst_loss_model") or {}
        if not model.get("enabled", False):
            return 0.0
        p_g2b = max(0.0, min(1.0, float(model.get("p_good_to_bad", 0.02))))
        p_b2g = max(0.0, min(1.0, float(model.get("p_bad_to_good", 0.25))))
        if self._downlink_ge_bad_state:
            if random.random() < p_b2g:
                self._downlink_ge_bad_state = False
        else:
            if random.random() < p_g2b:
                self._downlink_ge_bad_state = True
        if self._downlink_ge_bad_state:
            return max(0.0, min(1.0, float(model.get("loss_bad", 0.75))))
        return max(0.0, min(1.0, float(model.get("loss_good", 0.01))))

    # =============================
    # Abstract
    # =============================

    @abc.abstractmethod
    def ProcessRequest(self, msg, from_addr):
        pass