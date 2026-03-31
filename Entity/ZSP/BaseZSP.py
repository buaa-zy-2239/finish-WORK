from ns import ns
import cppyy
import abc
import os
import time
import json
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

        log_dir = "/home/zhang/UAV/logs"
        os.makedirs(log_dir, exist_ok=True)

        sim_id = int(time.time())
        self.log_file_path = os.path.join(
            log_dir, f"sim_{sim_id}_zsp_{zsp_id}.jsonl"
        )

        # ⭐ 持久打开文件（高性能）
        self.log_fp = open(self.log_file_path, "w", buffering=1)

    # =========================================================
    # 日志系统
    # =========================================================

    def _write_log(self, log_entry):
        self.log_fp.write(json.dumps(log_entry) + "\n")

    def _add_log(self, level, message, extra=None, log_type="SYSTEM"):
        log_entry = {
            "time": time.time(),
            "zsp_id": self.zsp_id,
            "level": level,       # DEBUG / LOG
            "type": log_type,     # D2Z / D2D / SYSTEM
            "message": message
        }

        if extra:
            log_entry["extra"] = extra

        self._write_log(log_entry)


    def log_debug(self, message, extra=None, log_type="SYSTEM"):
        self._add_log("DEBUG", message, extra, log_type)

    def log_info(self, message, extra=None, log_type="SYSTEM"):
        self._add_log("LOG", message, extra, log_type)
    # =============================
    # 容错核心
    # =============================

    def _safe_execute(self, tag, func, *args):
        try:
            return func(*args)
        except Exception as e:
            self.error_count += 1
            self.log_debug(f"[ZSP-{self.zsp_id}][ERROR][{tag}] {type(e).__name__}: {e}")

            if self.error_count > self.max_errors:
                self.log_debug(f"[ZSP-{self.zsp_id}] Too many errors → degraded mode")

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
            self.log_debug(f"[ZSP-{self.zsp_id}] GetAddress error: {e}")
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

            self.log_debug(f"[ZSP-{self.zsp_id}] Service Started")

            self._schedule_poll()

            if self.enable_blockchain:
                self._schedule_blockchain_poll()

        self._safe_execute("StartApplication", logic)

    def StopApplication(self):

        try:
            if self.m_socket:
                self.m_socket.Close()
        except Exception as e:
            self.log_debug(f"[ZSP-{self.zsp_id}] Stop error: {e}")

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
                    self.log_debug(f"[ZSP-{self.zsp_id}] Socket state error: {e}")
                    break

                try:
                    from_addr = ns.Address()
                    packet = self.m_socket.RecvFrom(from_addr)
                except Exception as e:
                    self.log_debug(f"[ZSP-{self.zsp_id}] Recv error: {e}")
                    break

                if not packet or packet.GetSize() == 0:
                    break

                try:
                    size = packet.GetSize()
                    buf = bytearray(size)
                    packet.CopyData(buf, size)

                    self.ProcessRequest(buf, from_addr)

                except Exception as e:
                    self.log_debug(f"[ZSP-{self.zsp_id}] Packet process error: {e}")

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

                self.log_debug(
                    f"[ZSP-{self.zsp_id}] CRP {old_crp} → {[challenge, response]}"
                )

                self._handle_pid_update(old_pid, new_pid)

                self.uav_db[new_pid]["crp"] = [challenge, response]

            except Exception as e:
                self.log_debug(f"[ZSP-{self.zsp_id}] Event error: {e}")

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

            self.log_debug(
                f"[ZSP-{self.zsp_id}] PID Sync "
                f"{old_pid[:8]} → {new_pid[:8]}"
            )

        except Exception as e:
            self.log_debug(f"[ZSP-{self.zsp_id}] PID sync error: {e}")

    # =============================
    # UAV 注册
    # =============================

    def RegisterUAV(self, pid, reg_info):

        def logic():

            if pid not in self.uav_db:
                self.uav_db[pid] = reg_info
                if not self.blockchain.is_valid_uav(pid):
                    self.blockchain.register_uav(pid)
            self.log_debug(f"[ZSP-{self.zsp_id}] Register UAV {pid[:8]}")
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

            self.log_debug(
                f"[ZSP-{self.zsp_id}] PID Update "
                f"{old_pid[:8]} → {new_pid[:8]}"
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