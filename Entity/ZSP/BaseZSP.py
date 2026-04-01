from ns import ns
import cppyy
import abc
import os
import time
import json
from Common.logging_framework import (
    ZSPLogger, DatabaseOperation, AuthenticationPhase, IdentifierOperation
)
from Entity.UAV.BaseUAV import BaseUAV


class BaseZSP(ns.Application):

    def __init__(self, node, zsp_id, blockchain=None, enable_blockchain=True):

        super().__init__()

        BaseUAV.ZSP_REGISTRY.append(self)

        self.node = node
        self.zsp_id = zsp_id

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

        # Poll refs
        self._poll_refs = []
        self._poll_interval = ns.MilliSeconds(100)

        # Blockchain poll
        self._bc_refs = []
        self._bc_poll_interval = ns.Seconds(1)

        if blockchain:
            self.last_event_block = blockchain.w3.eth.block_number - 1
        else:
            self.last_event_block = 0

        # 容错
        self.error_count = 0
        self.max_errors = 50

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

            self._schedule_poll()

            if self.enable_blockchain:
                self._schedule_blockchain_poll()

        self._safe_execute("StartApplication", logic)

    def StopApplication(self):

        try:
            if self.m_socket:
                self.m_socket.Close()
        except Exception as e:
            self.logger.log_error(f"Stop error: {e}", error_type="StopApplication")

    # =============================
    # Socket Poll
    # =============================

    def _schedule_poll(self):

        def cb():
            self._poll_socket()

        wrapper = cppyy.gbl.std.function['void()'](cb)

        self._poll_refs.append(cb)
        self._poll_refs.append(wrapper)

        ns.Simulator.Schedule(self._poll_interval, wrapper)

    def _poll_socket(self):

        def logic():

            while True:

                try:
                    if self.m_socket.GetRxAvailable() <= 0:
                        break
                except Exception as e:
                    self.logger.log_error(f"Socket state error: {e}", error_type="socket_state")
                    break

                try:
                    from_addr = ns.Address()
                    packet = self.m_socket.RecvFrom(from_addr)
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

        self._safe_execute("poll_socket", logic)

        self._schedule_poll()

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

                if old_pid not in self.uav_db:
                    continue

                old_crp = self.uav_db[old_pid].get("crp", ["?", "?"])

                challenge = e["challenge"]
                response = e["response"]

                self.logger.log_pid_rotation(
                    old_pid, new_pid,
                    old_crp=old_crp,
                    new_crp=[challenge, response]
                )

                self._handle_pid_update(old_pid, new_pid)

                self.uav_db[new_pid]["crp"] = [challenge, response]

            except Exception as e:
                self.logger.log_error(f"Event processing error: {e}", error_type="blockchain_event")

        self._schedule_blockchain_poll()

    # =============================
    # PID 同步
    # =============================

    def _handle_pid_update(self, old_pid, new_pid):

        try:
            if old_pid in self.uav_db:

                info = self.uav_db.pop(old_pid)
                info["pid"] = new_pid

                self.uav_db[new_pid] = info

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

            if old_pid in self.uav_db:

                info = self.uav_db.pop(old_pid)
                info["pid"] = new_pid

                self.uav_db[new_pid] = info

            self.logger.log_pid_rotation(
                    old_pid, new_pid,
                    new_crp=[new_challenge, new_response]
                )

            if self.enable_blockchain and self.blockchain:
                self.blockchain.update_pid(
                    old_pid, new_pid,
                    new_challenge, new_response
                )

        self._safe_execute("UpdateUAVPID", logic)

    # =============================
    # Send Packet
    # =============================

    def SendResponse(self, data_bytes, dest_addr):

        def logic():

            size = len(data_bytes)

            cpp_buffer = cppyy.gbl.std.vector['uint8_t'](size)

            for i in range(size):
                cpp_buffer[i] = data_bytes[i]

            packet = ns.Packet(cpp_buffer.data(), size)

            self.m_socket.SendTo(packet, 0, dest_addr)

        self._safe_execute("SendResponse", logic)

    # =============================
    # Abstract
    # =============================

    @abc.abstractmethod
    def ProcessRequest(self, msg, from_addr):
        pass