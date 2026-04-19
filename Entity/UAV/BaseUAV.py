from ns import ns
import abc
import cppyy
import math
from collections import deque
import random
import os
import time
import json
import uuid
from Common.scenario_inputs import normalize_auth_trigger_config, normalize_link_state_config
from Common.desync_experiment_hooks import emit_desync_pid_transition
from Common.logging_framework import (
    UAVLogger, AuthenticationPhase, IdentifierOperation
)

class BaseUAV(ns.Application):

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

        # 通信范围
        self.comm_range = 800

        # Handover hysteresis
        self.handover_margin = 5

        # 有界保留：蜂群规模下若无限 append，会拖垮内存并诱发 cling OOM / Simulator::Run 失败
        _cap = 262144
        self._poll_cb_refs = deque(maxlen=_cap)
        self._poll_wrapper_refs = deque(maxlen=_cap)
        self._event_refs = deque(maxlen=_cap)

        # Poll interval
        self._poll_interval = ns.MilliSeconds(100)

        # Mobility monitor interval
        self._mobility_interval = 0.3

        self.authenticated = False
        self.d2z_auth_session_id = None
        self.auth_trigger_config = normalize_auth_trigger_config(auth_trigger_config)
        self._auth_trigger_last_fire = {}
        self.link_state_config = normalize_link_state_config(link_state_config)
        self._last_link_zone = None
        self._last_out_of_range_state = False
        self._uplink_ge_bad_state = False

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

            self._install_recv_callback()

            self._safe_schedule(self._mobility_interval, self._mobility_monitor)
            self._schedule_auth_triggers()

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
            self._update_link_state_logs()
            self._evaluate_auth_triggers()

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
            self._auth_trigger_last_fire.pop("edge_rssi", None)
            self._auth_trigger_last_fire.pop("handover", None)

            self.Connect(addr)

            self.authenticated = False
            if old_zsp_id is not None:
                self.logger.log_disconnected_from_zsp(old_zsp_id, reason="handover")
            self.logger.log_debug(f"[UAV-{self.id}] Connected to ZSP-{zsp.zsp_id}")
            self.logger.log_connected_to_zsp(
                zsp.zsp_id,
                distance=self.DistanceTo(zsp.node),
                rssi=self.GetRSSI(zsp.node),
            )

            # `initial_on_connect` 只用于首次接入；handover 场景由 `on_handover` 单独控制，
            # 否则会在切换瞬间排入两次 D2Z_InitiateAuth（connect + handover window）。
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

        def logic():
            if self.auth_trigger_config.get("initial_on_connect", True):
                self._trigger_d2z_auth("D2Z_INITIATED")

        self._safe_execute("on_connected", logic)

    def _can_trigger_d2z_auth(self) -> bool:
        if self.current_zsp is None or self.zsp_id is None:
            return False
        if self.authenticated and not self.auth_trigger_config.get("allow_reauth", False):
            return False
        return True

    def _trigger_d2z_auth(self, protocol_step: str) -> bool:
        if not self._can_trigger_d2z_auth():
            return False
        link_state = self._get_link_state_snapshot()
        self.authenticated = False
        self.d2z_auth_session_id = str(uuid.uuid4())
        self.logger.log_authentication(
            AuthenticationPhase.INITIATED,
            peer_id=self.zsp_id,
            extra={
                "protocol": self.protocol_name,
                "analysis_family": self.analysis_family,
                "auth_session_id": self.d2z_auth_session_id,
                "flow": "D2Z",
                "protocol_step": protocol_step,
                "peer_zsp_id": self.zsp_id,
                "peer_uav_id": self.id,
                "distance_m": link_state.get("distance_m"),
                "rssi": link_state.get("rssi"),
                "link_zone": link_state.get("zone"),
                "block_reason": link_state.get("block_reason"),
            },
        )
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
        """去同步实验：本地 PID 已切换（子类在赋值 self.pid 后调用）。"""
        emit_desync_pid_transition(
            self,
            "uav",
            source,
            old_pid=old_pid,
            new_pid=new_pid,
        )

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
        if self.link_state_config.get("log_zone_changes", True) and zone != self._last_link_zone:
            self.logger.log_warning(
                f"Link zone changed to {zone}",
                warning_type="link_zone",
                extra={
                    "link_zone": zone,
                    "distance_m": state["distance_m"],
                    "rssi": state["rssi"],
                    "peer_zsp_id": self.zsp_id,
                    "peer_uav_id": self.id,
                },
            )
            self._last_link_zone = zone
        is_out = zone == "out_of_range"
        if is_out and not self._last_out_of_range_state:
            self.logger.log_out_of_range(
                extra={
                    "distance_m": state["distance_m"],
                    "rssi": state["rssi"],
                    "peer_zsp_id": self.zsp_id,
                    "peer_uav_id": self.id,
                }
            )
        self._last_out_of_range_state = is_out

    # =============================
    # Socket Receive Callback
    # =============================

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
            except Exception as e:
                self.logger.log_error(f"Packet error: {e}", error_type="packet_processing")

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
            uplink_loss_rate = float(self.link_state_config.get("uplink_loss_rate", 0.0) or 0.0)
            rssi_loss_rate = self._uplink_rssi_loss_rate()
            burst_loss_rate = self._uplink_burst_loss_rate()
            combined_loss_rate = 1.0 - (1.0 - uplink_loss_rate) * (1.0 - rssi_loss_rate) * (1.0 - burst_loss_rate)
            if combined_loss_rate > 0.0 and random.random() < combined_loss_rate:
                self.logger.log_warning(
                    "Probabilistic uplink drop injected",
                    warning_type="uplink_loss_injected",
                    extra={
                        "loss_rate": combined_loss_rate,
                        "uplink_loss_rate": uplink_loss_rate,
                        "rssi_loss_rate": rssi_loss_rate,
                        "burst_loss_rate": burst_loss_rate,
                        "peer_zsp_id": self.zsp_id,
                        "peer_uav_id": self.id,
                    },
                )
                return
            link_state = self._get_link_state_snapshot()
            if link_state["blocked"]:
                self.logger.log_warning(
                    f"Link blocked, dropping uplink payload: {link_state['block_reason']}",
                    warning_type="link_block",
                    extra={
                        "link_zone": link_state["zone"],
                        "distance_m": link_state["distance_m"],
                        "rssi": link_state["rssi"],
                        "block_reason": link_state["block_reason"],
                        "peer_zsp_id": self.zsp_id,
                        "peer_uav_id": self.id,
                    },
                )
                return

            size = len(payload_bytes)

            cpp_buffer = cppyy.gbl.std.vector['uint8_t'](size)

            for i in range(size):
                cpp_buffer[i] = payload_bytes[i]

            packet = ns.Packet(cpp_buffer.data(), size)

            self.m_socket.Send(packet)

        self._safe_execute("SendData", logic)

    def GetElevationAngle(self, zsp_node) -> float:
        """Calculate elevation angle from UAV to ZSP (degrees, 0 = horizon, 90 = zenith)."""
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
            return 45.0  # fallback

    def _uplink_rssi_loss_rate(self) -> float:
        model = self.link_state_config.get("rssi_loss_model") or {}
        if not model.get("enabled", False):
            return 0.0
        if self.current_zsp is None:
            return float(model.get("loss_bad", 0.5))
        elevation = self.GetElevationAngle(self.current_zsp.node)
        rssi = self.GetRSSI(self.current_zsp.node)
        rssi_good = float(model.get("rssi_good_dbm", -65.0))
        rssi_bad = float(model.get("rssi_bad_dbm", -90.0))
        loss_good = float(model.get("loss_good", 0.0))
        loss_bad = float(model.get("loss_bad", 0.5))
        # Elevation-aware adjustment (based on TWC 2025 and Mathematics 2025 models)
        # Higher elevation -> better LOS -> lower loss
        elevation_factor = max(0.0, min(1.0, (elevation - 10.0) / 60.0))  # 10° to 70°
        loss_bad = loss_bad * (1.0 - 0.6 * elevation_factor)
        if rssi_good <= rssi_bad:
            return max(loss_good, loss_bad)
        if rssi >= rssi_good:
            return loss_good
        if rssi <= rssi_bad:
            return loss_bad
        alpha = (rssi_good - rssi) / (rssi_good - rssi_bad)
        return loss_good + alpha * (loss_bad - loss_good)

    def _uplink_burst_loss_rate(self) -> float:
        model = self.link_state_config.get("uplink_burst_loss_model") or {}
        if not model.get("enabled", False):
            return 0.0
        p_g2b = max(0.0, min(1.0, float(model.get("p_good_to_bad", 0.02))))
        p_b2g = max(0.0, min(1.0, float(model.get("p_bad_to_good", 0.25))))
        if self._uplink_ge_bad_state:
            if random.random() < p_b2g:
                self._uplink_ge_bad_state = False
        else:
            if random.random() < p_g2b:
                self._uplink_ge_bad_state = True
        if self._uplink_ge_bad_state:
            return max(0.0, min(1.0, float(model.get("loss_bad", 0.8))))
        return max(0.0, min(1.0, float(model.get("loss_good", 0.02))))

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