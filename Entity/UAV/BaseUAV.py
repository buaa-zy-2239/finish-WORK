"""
UAV基类 - 提供UAV实体的基础功能
"""

from ns import ns
import abc
import cppyy
import math
from collections import deque
import random
import uuid

from Common.scenario_inputs import normalize_auth_trigger_config, normalize_link_state_config
from Common.desync_experiment_hooks import emit_desync_pid_transition
from Entity.common.safe_executor import SafeExecutor
from Entity.common.loss_models import BurstLossModel


class BaseUAV(ns.Application, SafeExecutor):
    """UAV基类，继承ns.Application和SafeExecutor"""

    ZSP_REGISTRY = []

    def __init__(
        self,
        node,
        uav_id,
        auth_trigger_config=None,
        link_state_config=None,
        protocol_name="GENERIC",
        analysis_family="D2Z",
    ):
        super().__init__()
        SafeExecutor._init_safe_executor(self)

        self.node = node
        self.id = uav_id
        self.protocol_name = protocol_name
        self.analysis_family = analysis_family

        self.m_socket = ns.Socket.CreateSocket(
            self.node,
            ns.TypeId.LookupByName("ns3::UdpSocketFactory")
        )

        self.peer_address = None
        self.peer_port = 9999
        self.current_zsp = None
        self.zsp_id = None

        self.comm_range = 800
        self.handover_margin = 5

        _cap = 262144
        self._poll_cb_refs = deque(maxlen=_cap)
        self._poll_wrapper_refs = deque(maxlen=_cap)
        self._poll_interval = ns.MilliSeconds(100)
        self._mobility_interval = 0.3

        self.authenticated = False
        self.d2z_auth_session_id = None
        self.auth_trigger_config = normalize_auth_trigger_config(auth_trigger_config)
        self._auth_trigger_last_fire = {}
        self.link_state_config = normalize_link_state_config(link_state_config)
        self._last_link_zone = None
        self._last_out_of_range_state = False
        self._last_send_dropped = False

        self._burst_loss_model = BurstLossModel(self.link_state_config.get("uplink_burst_loss_model"))

    def GetPosition(self):
        try:
            mobility = self.node.GetObject[ns.MobilityModel]()
            pos = mobility.GetPosition()
            return (pos.x, pos.y, pos.z)
        except Exception:
            return (0, 0, 0)

    def DistanceTo(self, node):
        try:
            m1 = self.node.GetObject[ns.MobilityModel]()
            m2 = node.GetObject[ns.MobilityModel]()
            return m1.GetDistanceFrom(m2)
        except Exception:
            return 99999

    def StartApplication(self):
        def logic():
            self.m_socket.Bind()
            self._install_recv_callback()
            self._safe_schedule(self._mobility_interval, self._mobility_monitor)
            self._schedule_auth_triggers()
            self.ScanZSP()
        self._safe_execute("StartApplication", logic)

    def StopApplication(self):
        try:
            if self.m_socket:
                self.m_socket.Close()
        except Exception:
            pass

    def _mobility_monitor(self):
        def logic():
            self.GetPosition()
            self.ScanZSP()
            self._update_link_state_logs()
            self._evaluate_auth_triggers()
        self._safe_execute("mobility_monitor", logic)
        self._safe_schedule(self._mobility_interval, self._mobility_monitor)

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
        except Exception:
            return -999

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
                return
            if self.current_zsp is None:
                self.SwitchConnection(best)
                return
            if best == self.current_zsp:
                return
            current_rssi = self.GetRSSI(self.current_zsp.node)
            if best_rssi - current_rssi > self.handover_margin:
                self.SwitchConnection(best)
        self._safe_execute("ScanZSP", logic)

    def SwitchConnection(self, zsp):
        def logic():
            addr = zsp.GetAddress()
            old_zsp_id = self.zsp_id
            self.current_zsp = zsp
            self.zsp_id = zsp.zsp_id
            self.peer_address = addr
            self._auth_trigger_last_fire.pop("edge_rssi", None)
            self._auth_trigger_last_fire.pop("handover", None)
            self.Connect(addr)
            self.authenticated = False
            if old_zsp_id is None:
                self.on_connected_to_zsp()
            elif self.auth_trigger_config.get("on_handover", False):
                self._safe_schedule(
                    self.auth_trigger_config.get("handover_delay_s", 0.5),
                    self._trigger_d2z_auth,
                    "D2Z_TRIGGER_HANDOVER_WINDOW",
                )
        self._safe_execute("SwitchConnection", logic)

    def on_connected_to_zsp(self):
        pass

    def _can_trigger_d2z_auth(self) -> bool:
        if self.current_zsp is None or self.zsp_id is None:
            return False
        if self.authenticated and not self.auth_trigger_config.get("allow_reauth", False):
            return False
        return True

    def _trigger_d2z_auth(self, protocol_step: str) -> bool:
        if not self._can_trigger_d2z_auth():
            return False
        self.authenticated = False
        self.d2z_auth_session_id = str(uuid.uuid4())
        self._safe_schedule(0.5, self.D2Z_InitiateAuth)
        return True

    def get_registration_record(self):
        return {
            "uav_id": self.id,
            "pid": getattr(self, "pid", None),
            "crp": getattr(self, "crp", None),
            "protocol": self.protocol_name,
            "analysis_family": self.analysis_family,
        }

    def _desync_notify_local_pid(self, old_pid, new_pid, source: str) -> None:
        emit_desync_pid_transition(self, "uav", source, old_pid=old_pid, new_pid=new_pid)

    def _schedule_auth_triggers(self):
        for t in self.auth_trigger_config.get("time_offsets_s", []):
            self._safe_schedule(float(t), self._trigger_d2z_auth, "D2Z_TRIGGER_TIME")

    def _evaluate_auth_triggers(self):
        threshold = self.auth_trigger_config.get("edge_rssi_threshold")
        if threshold is None or self.current_zsp is None:
            return
        cooldown_s = float(self.auth_trigger_config.get("cooldown_s", 3.0))
        now = ns.Simulator.Now().GetSeconds()
        last = self._auth_trigger_last_fire.get("edge_rssi", 0.0)
        if now - last < cooldown_s:
            return
        rssi = self.GetRSSI(self.current_zsp.node)
        if rssi <= threshold and self._trigger_d2z_auth("D2Z_TRIGGER_EDGE_RSSI"):
            self._auth_trigger_last_fire["edge_rssi"] = now

    def _get_link_state_snapshot(self):
        if self.current_zsp is None:
            return {
                "distance_m": None,
                "rssi": None,
                "zone": "disconnected",
                "blocked": False,
                "block_reason": None,
            }
        distance_m = self.DistanceTo(self.current_zsp.node)
        rssi = self.GetRSSI(self.current_zsp.node)
        zone = "core"
        comm_range = self.link_state_config.get("comm_range_m", 800)
        edge_rssi = self.link_state_config.get("edge_rssi_threshold")
        if distance_m > comm_range:
            zone = "out_of_range"
        elif edge_rssi is not None and rssi <= edge_rssi:
            zone = "edge"
        now = ns.Simulator.Now().GetSeconds()
        block_reason = None
        blocked = False
        for window in self.link_state_config.get("loss_windows", []):
            if window["start_s"] <= now <= window["end_s"]:
                blocked = True
                block_reason = window.get("reason", "scheduled_loss_window")
                break
        if zone == "out_of_range" and self.link_state_config.get("drop_when_out_of_range", True):
            blocked = True
            block_reason = block_reason or "out_of_range"
        return {
            "distance_m": distance_m,
            "rssi": rssi,
            "zone": zone,
            "blocked": blocked,
            "block_reason": block_reason,
        }

    def _update_link_state_logs(self):
        if self.current_zsp is None:
            return
        state = self._get_link_state_snapshot()
        zone = state["zone"]
        if zone != self._last_link_zone:
            self._last_link_zone = zone
        is_out = zone == "out_of_range"
        self._last_out_of_range_state = is_out

    def _install_recv_callback(self):
        def on_recv(sock):
            self._safe_execute("recv_callback", self._drain_socket_packets, sock)
        wrapper = cppyy.gbl.std.function['void(ns3::Ptr<ns3::Socket>)'](on_recv)
        self._poll_cb_refs.append(on_recv)
        self._poll_wrapper_refs.append(wrapper)
        self.m_socket.SetRecvCallback(wrapper)

    def _drain_socket_packets(self, sock=None):
        sock_obj = sock if sock is not None else self.m_socket
        while True:
            try:
                if sock_obj.GetRxAvailable() <= 0:
                    break
            except Exception:
                break
            try:
                from_addr = ns.Address()
                packet = sock_obj.RecvFrom(from_addr)
            except Exception:
                break
            if not packet or packet.GetSize() == 0:
                break
            try:
                size = packet.GetSize()
                buf = bytearray(size)
                packet.CopyData(buf, size)
                self.ProcessReceivedData(buf)
            except Exception:
                pass

    def Connect(self, zsp_address, zsp_port=9999):
        def logic():
            inet_addr = ns.InetSocketAddress(zsp_address, zsp_port)
            final_addr = inet_addr.ConvertTo()
            self.m_socket.Connect(final_addr)
        self._safe_execute("Connect", logic)

    def SendData(self, payload_bytes, message_type=None):
        def logic():
            uplink_loss_rate = float(self.link_state_config.get("uplink_loss_rate", 0.0) or 0.0)
            burst_loss_rate = self._burst_loss_model.get_loss_rate()
            combined_loss_rate = 1.0 - (1.0 - uplink_loss_rate) * (1.0 - burst_loss_rate)
            if combined_loss_rate > 0.0 and random.random() < combined_loss_rate:
                self._last_send_dropped = True
                return False
            link_state = self._get_link_state_snapshot()
            if link_state["blocked"]:
                self._last_send_dropped = True
                return False
            size = len(payload_bytes)
            cpp_buffer = cppyy.gbl.std.vector['uint8_t'](size)
            for i in range(size):
                cpp_buffer[i] = payload_bytes[i]
            packet = ns.Packet(cpp_buffer.data(), size)
            if hasattr(self, 'peer_address') and self.peer_address is not None:
                addr = ns.InetSocketAddress(self.peer_address, 9999)
                self.m_socket.SendTo(packet, 0, addr.ConvertTo())
            else:
                self.m_socket.Send(packet)
            self._last_send_dropped = False
            return True
        return self._safe_execute("SendData", logic)

    def GetElevationAngle(self, zsp_node) -> float:
        try:
            pos_u = self.GetPosition()
            mobility = zsp_node.GetObject[ns.MobilityModel]()
            pos_z = (mobility.GetPosition().x, mobility.GetPosition().y, mobility.GetPosition().z)
            dx = pos_z[0] - pos_u[0]
            dy = pos_z[1] - pos_u[1]
            dz = pos_z[2] - pos_u[2]
            horizontal = math.sqrt(dx*dx + dy*dy)
            dist = math.sqrt(horizontal*horizontal + dz*dz)
            if dist < 1e-6:
                return 90.0
            return math.degrees(math.asin(dz / dist))
        except Exception:
            return 45.0

    @abc.abstractmethod
    def ProcessReceivedData(self, msg):
        pass