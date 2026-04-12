from ns import ns
import abc
import cppyy
import math
import os
import time
import json
import uuid
from Common.logging_framework import (
    UAVLogger, AuthenticationPhase, IdentifierOperation
)

class BaseUAV(ns.Application):

    ZSP_REGISTRY = []

    def __init__(self, node, uav_id):

        super().__init__()

        self.node = node
        self.id = uav_id

        self.m_socket = ns.Socket.CreateSocket(
            self.node,
            ns.TypeId.LookupByName("ns3::UdpSocketFactory")
        )

        self.peer_address = None
        self.peer_port = 9999

        self.current_zsp = None
        self.zsp_id = None

        # 通信范围
        self.comm_range = 300

        # Handover hysteresis
        self.handover_margin = 5

        # Scheduler refs (防止 GC)
        self._poll_cb_refs = []
        self._poll_wrapper_refs = []
        self._event_refs = []

        # Poll interval
        self._poll_interval = ns.MilliSeconds(100)

        # Mobility monitor interval
        self._mobility_interval = 0.3

        self.authenticated = False
        self.d2z_auth_session_id = None

        # 容错机制
        self.error_count = 0
        self.max_errors = 50
        self.logger = UAVLogger(uav_id)

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
                self.logger.log_error("Too many errors - disabling further execution")

    # =============================
    # Mobility
    # =============================

    def GetPosition(self):
        try:
            mobility = self.node.GetObject[ns.MobilityModel]()
            pos = mobility.GetPosition()
            return (pos.x, pos.y, pos.z)
        except Exception as e:
            self.logger.log_error(f"GetPosition error: {e}", error_type="GetPosition")
            return (0, 0, 0)

    def DistanceTo(self, node):
        try:
            m1 = self.node.GetObject[ns.MobilityModel]()
            m2 = node.GetObject[ns.MobilityModel]()
            return m1.GetDistanceFrom(m2)
        except Exception as e:
            self.logger.log_error(f"Distance error: {e}", error_type="DistanceTo")
            return 99999

    # =============================
    # Application 生命周期
    # =============================

    def StartApplication(self):

        def logic():

            self.m_socket.Bind()

            self.logger.log_debug(f"[UAV-{self.id}] Application Started")

            self._schedule_poll()

            self._safe_schedule(self._mobility_interval, self._mobility_monitor)

            self.ScanZSP()

        self._safe_execute("StartApplication", logic)

    def StopApplication(self):

        try:
            if self.m_socket:
                self.m_socket.Close()
        except Exception as e:
            self.logger.log_error(f"Stop error: {e}", error_type="StopApplication")

    # =============================
    # Mobility Monitor
    # =============================

    def _mobility_monitor(self):

        def logic():
            self.GetPosition()
            self.ScanZSP()

        self._safe_execute("mobility_monitor", logic)

        self._safe_schedule(self._mobility_interval, self._mobility_monitor)

    # =============================
    # RSSI
    # =============================

    def GetRSSI(self, node):

        try:
            m1 = self.node.GetObject[ns.MobilityModel]()
            m2 = node.GetObject[ns.MobilityModel]()

            dist = m1.GetDistanceFrom(m2)
            if dist < 1:
                dist = 1

            freq = 2.4e9
            c = 3e8
            wavelength = c / freq

            pr0 = (wavelength / (4 * math.pi)) ** 2
            n = 2.7
            pr = pr0 / (dist ** n)

            return 10 * math.log10(pr) + 20

        except Exception as e:
            self.logger.log_error(f"RSSI error: {e}", error_type="GetRSSI")
            return -999

    # =============================
    # ZSP 扫描
    # =============================

    def ScanZSP(self):

        def logic():

            best = None
            best_rssi = -999

            for zsp in BaseUAV.ZSP_REGISTRY:

                try:
                    rssi = self.GetRSSI(zsp.node)
                except:
                    continue

                if rssi > best_rssi:
                    best = zsp
                    best_rssi = rssi

            if best is None:
                self.logger.log_warning("No ZSP in range", warning_type="coverage")
                self.logger.log_out_of_range()
                return

            if self.current_zsp is None:
                self.SwitchConnection(best)
                return

            if best == self.current_zsp:
                return

            current_rssi = self.GetRSSI(self.current_zsp.node)

            if best_rssi - current_rssi > self.handover_margin:
                self.logger.log_handover(
                    self.zsp_id, 
                    best.zsp_id,
                    from_rssi=current_rssi,
                    to_rssi=best_rssi
                )
                self.SwitchConnection(best)

        self._safe_execute("ScanZSP", logic)

    # =============================
    # 切换连接
    # =============================

    def SwitchConnection(self, zsp):

        def logic():

            addr = zsp.GetAddress()

            old_zsp_id = self.zsp_id
            self.current_zsp = zsp
            self.zsp_id = zsp.zsp_id
            self.peer_address = addr

            self.Connect(addr)

            self.authenticated = False
            if old_zsp_id is not None:
                self.logger.log_disconnected_from_zsp(old_zsp_id, reason="handover")
            self.logger.log_debug(f"[UAV-{self.id}] Connected to ZSP-{zsp.zsp_id}")

            self.on_connected_to_zsp()

        self._safe_execute("SwitchConnection", logic)

    def on_connected_to_zsp(self):

        def logic():
            if not self.authenticated:
                self.d2z_auth_session_id = str(uuid.uuid4())
                self.logger.log_authentication(
                    AuthenticationPhase.INITIATED,
                    peer_id=self.zsp_id,
                    extra={
                        "auth_session_id": self.d2z_auth_session_id,
                        "flow": "D2Z",
                        "protocol_step": "D2Z_INITIATED",
                        "peer_zsp_id": self.zsp_id,
                        "peer_uav_id": self.id,
                    },
                )
                self._safe_schedule(0.5, self.D2Z_InitiateAuth)

        self._safe_execute("on_connected", logic)

    # =============================
    # Socket Poll
    # =============================

    def _schedule_poll(self):

        def cb():
            self._poll_socket()

        wrapper = cppyy.gbl.std.function['void()'](cb)

        self._poll_cb_refs.append(cb)
        self._poll_wrapper_refs.append(wrapper)

        ns.Simulator.Schedule(self._poll_interval, wrapper)

    def _poll_socket(self):

        def logic():

            while True:

                try:
                    if self.m_socket.GetRxAvailable() <= 0:
                        break
                except:
                    break

                try:
                    from_addr = ns.Address()
                    packet = self.m_socket.RecvFrom(from_addr)
                except:
                    break

                if not packet or packet.GetSize() == 0:
                    break

                try:
                    size = packet.GetSize()
                    buf = bytearray(size)
                    packet.CopyData(buf, size)

                    self.ProcessReceivedData(buf)

                except Exception as e:
                    self.logger.log_error(f"Packet error: {e}", error_type="packet_processing")

        self._safe_execute("poll_socket", logic)

        self._schedule_poll()

    # =============================
    # 网络接口
    # =============================

    def Connect(self, zsp_address, zsp_port=9999):

        def logic():

            inet_addr = ns.InetSocketAddress(zsp_address, zsp_port)
            final_addr = inet_addr.ConvertTo()

            self.m_socket.Connect(final_addr)

            self.logger.log_debug(f"Connected to {zsp_address}:{zsp_port}")

        self._safe_execute("Connect", logic)

    def SendData(self, payload_bytes):

        def logic():

            size = len(payload_bytes)

            cpp_buffer = cppyy.gbl.std.vector['uint8_t'](size)

            for i in range(size):
                cpp_buffer[i] = payload_bytes[i]

            packet = ns.Packet(cpp_buffer.data(), size)

            self.m_socket.Send(packet)

        self._safe_execute("SendData", logic)

    # =============================
    # 抽象方法
    # =============================

    @abc.abstractmethod
    def ProcessReceivedData(self, msg):
        pass

    # =============================
    # Safe Scheduler
    # =============================

    def _safe_schedule(self, delay_sec, func, *args):

        def wrapper():
            self._safe_execute(func.__name__, func, *args)

        event_cb = cppyy.gbl.std.function['void()'](wrapper)

        self._event_refs.append(wrapper)
        self._event_refs.append(event_cb)

        ns.Simulator.Schedule(ns.Seconds(delay_sec), event_cb)