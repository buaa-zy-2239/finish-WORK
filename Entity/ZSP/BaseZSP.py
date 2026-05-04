"""
ZSP基类 - 提供ZSP实体的基础功能
"""

from ns import ns
import cppyy
from collections import deque

from Entity.UAV.BaseUAV import BaseUAV
from Entity.common.safe_executor import SafeExecutor
from Entity.common.loss_models import BurstLossModel
from Common.crp_chain_codec import canonicalize_crp_pair
from Common.desync_experiment_hooks import emit_desync_pid_transition


class BaseZSP(ns.Application, SafeExecutor):
    """ZSP基类，继承ns.Application和SafeExecutor"""

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
        SafeExecutor._init_safe_executor(self)

        BaseUAV.ZSP_REGISTRY.append(self)

        self.node = node
        self.zsp_id = zsp_id
        self.protocol_name = protocol_name
        self.analysis_family = analysis_family

        self.enable_blockchain = enable_blockchain
        self.blockchain = blockchain

        self.uav_db = {}

        self.m_socket = ns.Socket.CreateSocket(
            self.node,
            ns.TypeId.LookupByName("ns3::UdpSocketFactory")
        )
        self.m_socket.SetAllowBroadcast(True)

        _cap = 262144
        self._poll_refs = deque(maxlen=_cap)
        self._poll_interval = ns.MilliSeconds(100)
        self._bc_refs = deque(maxlen=_cap)
        self._bc_poll_interval = ns.Seconds(1)

        if blockchain:
            self.last_event_block = blockchain.w3.eth.block_number - 1
        else:
            self.last_event_block = 0

        self._downlink_burst_loss_model = BurstLossModel({})

    def _install_mobility(self):
        def logic():
            mobility = self.node.GetObject[ns.MobilityModel]()
            if mobility:
                return
            from ns import ns
            helper = ns.MobilityHelper()
            helper.SetMobilityModel("ns3::ConstantPositionMobilityModel")
            container = ns.NodeContainer()
            container.Add(self.node)
            helper.Install(container)
            mobility = self.node.GetObject[ns.MobilityModel]()
            mobility.SetPosition(ns.Vector(self.zsp_id * 500, 0, 100))
        self._safe_execute("install_mobility", logic)

    def GetAddress(self):
        try:
            ipv4 = self.node.GetObject[ns.Ipv4]()
            addr = ipv4.GetAddress(1, 0)
            return addr.GetLocal()
        except Exception:
            return ns.Ipv4Address("0.0.0.0")

    def StartApplication(self):
        def logic():
            local_address = ns.InetSocketAddress(ns.Ipv4Address.GetAny(), 9999)
            self.m_socket.Bind(local_address.ConvertTo())
            self._install_recv_callback()
            if self.enable_blockchain and self.blockchain:
                self._schedule_blockchain_poll()
        self._safe_execute("StartApplication", logic)

    def StopApplication(self):
        try:
            if self.m_socket:
                self.m_socket.Close()
        except Exception:
            pass

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
                self.ProcessRequest(buf, from_addr)
            except Exception:
                pass

    def _schedule_blockchain_poll(self):
        def wrapper():
            self._safe_execute("blockchain_poll", self._poll_blockchain_events)
        cb = cppyy.gbl.std.function['void()'](wrapper)
        self._bc_refs.append(wrapper)
        self._bc_refs.append(cb)
        ns.Simulator.Schedule(self._bc_poll_interval, cb)

    def _poll_blockchain_events(self):
        latest = self.blockchain.w3.eth.block_number
        events = self.blockchain.get_pid_update_events(self.last_event_block + 1, latest)
        self.last_event_block = latest
        for e in events:
            try:
                old_pid = e["old_pid"]
                new_pid = e["new_pid"]
                challenge, response = canonicalize_crp_pair(float(e["challenge"]), float(e["response"]))
                if old_pid not in self.uav_db:
                    if new_pid in self.uav_db:
                        self.uav_db[new_pid]["crp"] = [challenge, response]
                    continue
                self._handle_pid_update(old_pid, new_pid)
                self.uav_db[new_pid]["crp"] = [challenge, response]
            except Exception:
                pass
        self._schedule_blockchain_poll()

    def _handle_pid_update(self, old_pid, new_pid):
        try:
            if old_pid in self.uav_db:
                info = self.uav_db.pop(old_pid)
                info["pid"] = new_pid
                self.uav_db[new_pid] = info
                emit_desync_pid_transition(self, "zsp", "_handle_pid_update", old_pid=old_pid, new_pid=new_pid)
        except Exception:
            pass

    def RegisterUAV(self, pid, reg_info):
        def logic():
            if pid not in self.uav_db:
                self.uav_db[pid] = reg_info
                if self.enable_blockchain and self.blockchain:
                    if hasattr(self.blockchain, 'is_valid_uav') and hasattr(self.blockchain, 'register_uav'):
                        if not self.blockchain.is_valid_uav(pid):
                            self.blockchain.register_uav(pid)
        self._safe_execute("RegisterUAV", logic)

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
            if self.enable_blockchain and self.blockchain:
                self.blockchain.update_pid(old_pid, new_pid, nc, nr)
            if mutated:
                emit_desync_pid_transition(self, "zsp", "UpdateUAVPID", old_pid=old_pid, new_pid=new_pid)
        self._safe_execute("UpdateUAVPID", logic)

    def SendResponse(self, data_bytes, dest_addr):
        def logic():
            attack_model = getattr(self, "attack_model", {}) or {}
            downlink_loss_rate = float(attack_model.get("downlink_loss_rate", 0.0) or 0.0)
            burst_loss_rate = self._get_downlink_burst_loss_rate(attack_model)
            combined_loss_rate = 1.0 - (1.0 - downlink_loss_rate) * (1.0 - burst_loss_rate)
            if combined_loss_rate > 0.0 and self._should_drop():
                return
            size = len(data_bytes)
            cpp_buffer = cppyy.gbl.std.vector['uint8_t'](size)
            for i in range(size):
                cpp_buffer[i] = data_bytes[i]
            packet = ns.Packet(cpp_buffer.data(), size)
            self.m_socket.SendTo(packet, 0, dest_addr)
        self._safe_execute("SendResponse", logic)

    def _get_downlink_burst_loss_rate(self, attack_model: dict) -> float:
        model = attack_model.get("downlink_burst_loss_model") or {}
        self._downlink_burst_loss_model.enabled = bool(model.get("enabled", False))
        self._downlink_burst_loss_model.p_good_to_bad = float(model.get("p_good_to_bad", 0.02))
        self._downlink_burst_loss_model.p_bad_to_good = float(model.get("p_bad_to_good", 0.25))
        self._downlink_burst_loss_model.loss_bad = float(model.get("loss_bad", 0.75))
        self._downlink_burst_loss_model.loss_good = float(model.get("loss_good", 0.01))
        return self._downlink_burst_loss_model.get_loss_rate()

    def _should_drop(self) -> bool:
        import random
        return random.random() < self._downlink_burst_loss_model.get_loss_rate()

    @property
    def _downlink_ge_bad_state(self):
        return self._downlink_burst_loss_model._in_bad_state

    @_downlink_ge_bad_state.setter
    def _downlink_ge_bad_state(self, value):
        self._downlink_burst_loss_model._in_bad_state = value