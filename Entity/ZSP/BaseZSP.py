from ns import ns
import cppyy
import abc

from Entity.UAV.BaseUAV import BaseUAV


class BaseZSP(ns.Application):

    def __init__(self, node, zsp_id, blockchain=None, enable_blockchain=True):

        super().__init__()

        BaseUAV.ZSP_REGISTRY.append(self)

        self.node = node
        self.zsp_id = zsp_id

        self.enable_blockchain = enable_blockchain
        self.blockchain = blockchain

        # =============================
        # UAV 本地数据库
        # =============================

        self.uav_db = {}

        # =============================
        # UDP Socket
        # =============================

        self.m_socket = ns.Socket.CreateSocket(
            self.node,
            ns.TypeId.LookupByName("ns3::UdpSocketFactory")
        )

        self.m_socket.SetAllowBroadcast(True)

        # =============================
        # Poll references
        # =============================

        self._poll_refs = []
        self._poll_interval = ns.MilliSeconds(100)

        # =============================
        # Blockchain poll
        # =============================

        self._bc_refs = []
        self._bc_poll_interval = ns.Seconds(1)

        if blockchain:
            self.last_event_block = blockchain.w3.eth.block_number - 1
        else:
            self.last_event_block = 0

        # =============================
        # Mobility
        # =============================

        self._install_mobility()

    # ==================================================
    # Mobility
    # ==================================================

    def _install_mobility(self):

        mobility = self.node.GetObject[ns.MobilityModel]()

        if mobility:
            return

        helper = ns.MobilityHelper()

        helper.SetMobilityModel(
            "ns3::ConstantPositionMobilityModel"
        )

        container = ns.NodeContainer()
        container.Add(self.node)

        helper.Install(container)

        mobility = self.node.GetObject[ns.MobilityModel]()

        mobility.SetPosition(
            ns.Vector(self.zsp_id * 500, 0, 100)
        )

    # ==================================================
    # Address
    # ==================================================

    def GetAddress(self):

        ipv4 = self.node.GetObject[ns.Ipv4]()
        addr = ipv4.GetAddress(1, 0)

        return addr.GetLocal()

    # ==================================================
    # 生命周期
    # ==================================================

    def StartApplication(self):

        local_address = ns.InetSocketAddress(
            ns.Ipv4Address.GetAny(),
            9999
        )

        self.m_socket.Bind(local_address.ConvertTo())

        print(f"[ZSP-{self.zsp_id}] Service Started")

        self._schedule_poll()

        if self.enable_blockchain:
            self._schedule_blockchain_poll()

    def StopApplication(self):

        if self.m_socket:
            self.m_socket.Close()

    # ==================================================
    # Socket Poll
    # ==================================================

    def _schedule_poll(self):

        def cb():
            self._poll_socket()

        wrapper = cppyy.gbl.std.function['void()'](cb)

        self._poll_refs.append(cb)
        self._poll_refs.append(wrapper)

        ns.Simulator.Schedule(self._poll_interval, wrapper)

    def _poll_socket(self):

        while self.m_socket.GetRxAvailable() > 0:

            from_addr = ns.Address()

            packet = self.m_socket.RecvFrom(from_addr)

            if not packet or packet.GetSize() == 0:
                break

            size = packet.GetSize()
            buf = bytearray(size)

            packet.CopyData(buf, size)

            try:

                msg = buf.decode("utf-8")
                self.ProcessRequest(msg, from_addr)

            except UnicodeDecodeError:

                print(f"[ZSP-{self.zsp_id}] Decode Error")

        self._schedule_poll()

    # ==================================================
    # Blockchain Poll
    # ==================================================

    def _schedule_blockchain_poll(self):

        def cb():
            self._poll_blockchain_events()

        wrapper = cppyy.gbl.std.function['void()'](cb)

        self._bc_refs.append(cb)
        self._bc_refs.append(wrapper)

        ns.Simulator.Schedule(self._bc_poll_interval, wrapper)

    def _poll_blockchain_events(self):

        try:

            latest = self.blockchain.w3.eth.block_number

            events = self.blockchain.get_pid_update_events(
                self.last_event_block + 1,
                latest
            )

            self.last_event_block = latest

            for e in events:

                old_pid = e["old_pid"]
                new_pid = e["new_pid"]
                if old_pid not in self.uav_db:
                    continue
                old_crp = self.uav_db[old_pid]["crp"]
                
                challenge = e["challenge"]
                response = e["response"]
                print(f"[ZSP-{self.zsp_id}] CRP Event: {old_crp[0]},{old_crp[1]} -> {challenge},{response}")
                print(
                    f"[ZSP-{self.zsp_id}] PID Event "
                    f"{old_pid[:6]} -> {new_pid[:6]}"
                )
                self._handle_pid_update(old_pid, new_pid)
                self.uav_db[new_pid]["crp"] = [challenge,response]

        except Exception as e:

            print(f"[ZSP-{self.zsp_id}] Blockchain Poll Error: {e}")

        self._schedule_blockchain_poll()

    # ==================================================
    # PID 同步
    # ==================================================

    def _handle_pid_update(self, old_pid, new_pid):

        if old_pid in self.uav_db:

            info = self.uav_db.pop(old_pid)
            info["pid"] = new_pid

            self.uav_db[new_pid] = info

        else:
            return
            self.uav_db[new_pid] = {
                "pid": new_pid
            }

        print(
            f"[ZSP-{self.zsp_id}] PID Sync "
            f"{old_pid[:8]} -> {new_pid[:8]}"
        )

    # ==================================================
    # UAV 注册
    # ==================================================

    def RegisterUAV(self, pid, reg_info):
        if pid not in self.uav_db:
            self.uav_db[pid] = reg_info

        print(
            f"[ZSP-{self.zsp_id}] Register UAV {pid[:8]}"
        )

        if self.enable_blockchain:

            try:
                if self.zsp_id == 0:
                    self.blockchain.register_uav(pid)

            except Exception as e:

                print(
                    f"[ZSP-{self.zsp_id}] Blockchain register fail {e}"
                )

    # ==================================================
    # PID 更新
    # ==================================================

    def UpdateUAVPID(self, old_pid, new_pid, new_challenge, new_response):

        if old_pid in self.uav_db:

            info = self.uav_db.pop(old_pid)

            info["pid"] = new_pid

            self.uav_db[new_pid] = info

        print(
            f"[ZSP-{self.zsp_id}] PID Update "
            f"{old_pid[:8]} -> {new_pid[:8]}"
        )

        if self.enable_blockchain:

            try:

                self.blockchain.update_pid(old_pid, new_pid, new_challenge, new_response)

            except Exception as e:

                print(
                    f"[ZSP-{self.zsp_id}] Blockchain update fail {e}"
                )

    # ==================================================
    # Send Packet
    # ==================================================

    def SendResponse(self, payload_str, dest_addr):

        data_bytes = payload_str.encode('utf-8')

        size = len(data_bytes)

        cpp_buffer = cppyy.gbl.std.vector['uint8_t'](size)

        for i in range(size):
            cpp_buffer[i] = data_bytes[i]

        packet = ns.Packet(cpp_buffer.data(), size)

        self.m_socket.SendTo(packet, 0, dest_addr)

    # ==================================================
    # Abstract
    # ==================================================

    @abc.abstractmethod
    def ProcessRequest(self, msg_str, from_addr):
        pass