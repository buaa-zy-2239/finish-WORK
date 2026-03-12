from ns import ns
import abc
import cppyy
import math


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

        self.comm_range = 300

        self._poll_cb_refs = []
        self._poll_wrapper_refs = []
        self._event_refs = []
        

        self._poll_interval = ns.MilliSeconds(100)

        self.authenticated = False

        self._install_mobility()

    # =============================
    # Mobility
    # =============================

    def _install_mobility(self):

        mobility = self.node.GetObject[ns.MobilityModel]()

        if mobility:
            return

        helper = ns.MobilityHelper()

        helper.SetMobilityModel(
            "ns3::ConstantVelocityMobilityModel"
        )

        container = ns.NodeContainer()
        container.Add(self.node)

        helper.Install(container)

        mobility = self.node.GetObject[ns.ConstantVelocityMobilityModel]()

        mobility.SetPosition(ns.Vector(self.id * 50, 0, 50))

        mobility.SetVelocity(ns.Vector(10, 0, 0))

    def GetPosition(self):

        mobility = self.node.GetObject[ns.MobilityModel]()
        pos = mobility.GetPosition()

        return (pos.x, pos.y, pos.z)

    def DistanceTo(self, node):

        m1 = self.node.GetObject[ns.MobilityModel]()
        m2 = node.GetObject[ns.MobilityModel]()

        return m1.GetDistanceFrom(m2)

    # =============================
    # Application 生命周期
    # =============================

    def StartApplication(self):

        self.m_socket.Bind()

        print(f"[UAV-{self.id}] Application Started")

        self._schedule_poll()

        self._safe_schedule(1, self._mobility_monitor)
        self.ScanZSP()

    def StopApplication(self):

        if self.m_socket:
            self.m_socket.Close()

    # =============================
    # Mobility Monitor
    # =============================

    def _mobility_monitor(self):

        x, y, z = self.GetPosition()

        if self.current_zsp:

            dist = self.DistanceTo(self.current_zsp.node)

            if dist > self.comm_range:

                print(f"[UAV-{self.id}] Lost ZSP-{self.current_zsp.zsp_id}")

                self.current_zsp = None
                self.authenticated = False

                self.ScanZSP()

        else:

            self.ScanZSP()

        self._safe_schedule(1, self._mobility_monitor)

    # =============================
    # RSSI
    # =============================

    def GetRSSI(self, node):

        m1 = self.node.GetObject[ns.MobilityModel]()
        m2 = node.GetObject[ns.MobilityModel]()

        dist = m1.GetDistanceFrom(m2)

        freq = 2.4e9
        c = 3e8
        wavelength = c / freq

        if dist == 0:
            dist = 0.1

        pr = (wavelength / (4 * math.pi * dist)) ** 2

        rssi_dbm = 10 * math.log10(pr) + 20

        return rssi_dbm

    # =============================
    # ZSP 扫描
    # =============================

    def ScanZSP(self):

        best = None
        best_rssi = -999

        for zsp in BaseUAV.ZSP_REGISTRY:

            rssi = self.GetRSSI(zsp.node)

            if rssi > best_rssi:
                best = zsp
                best_rssi = rssi

        if best and best != self.current_zsp:

            self.SwitchConnection(best)

    # =============================
    # 切换连接
    # =============================

    def SwitchConnection(self, zsp):

        addr = zsp.GetAddress()

        self.current_zsp = zsp
        self.zsp_id = zsp.zsp_id

        self.peer_address = addr

        self.Connect(addr)

        print(f"[UAV-{self.id}] Connected to ZSP-{zsp.zsp_id}")
        self.on_connected_to_zsp()

    # =============================
    # 连接回调
    # =============================

    def on_connected_to_zsp(self):

        if not self.authenticated:

            print(f"[UAV-{self.id}] Trigger D2Z Authentication")

            if hasattr(self, "Start_D2Z_AuthLater"):
                self.Start_D2Z_AuthLater(0.5)

    # =============================
    # Poll Socket
    # =============================

    def _schedule_poll(self):

        cb = lambda: self._poll_socket()
        wrapper = cppyy.gbl.std.function['void()'](cb)

        self._poll_cb_refs.append(cb)
        self._poll_wrapper_refs.append(wrapper)

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

                self.ProcessReceivedData(msg)

            except UnicodeDecodeError:

                print(f"[UAV-{self.id}] Decode Error")

        self._schedule_poll()

    # =============================
    # 网络接口
    # =============================

    def Connect(self, zsp_address, zsp_port=9999):

        inet_addr = ns.InetSocketAddress(zsp_address, zsp_port)

        final_addr = inet_addr.ConvertTo()

        self.m_socket.Connect(final_addr)

        print(f"[DEBUG] UAV-{self.id} connected to {zsp_address}:{zsp_port}")

    def SendData(self, payload_str):

        data_bytes = payload_str.encode('utf-8')

        size = len(data_bytes)

        cpp_buffer = cppyy.gbl.std.vector['uint8_t'](size)

        for i in range(size):
            cpp_buffer[i] = data_bytes[i]

        packet = ns.Packet(cpp_buffer.data(), size)

        self.m_socket.Send(packet)

    # =============================
    # 抽象方法
    # =============================

    @abc.abstractmethod
    def ProcessReceivedData(self, msg_str):
        pass

    # =============================
    # Safe Scheduler
    # =============================

    def _safe_schedule(self, delay_sec, func, *args):

        def wrapper():
            func(*args)

        event_cb = cppyy.gbl.std.function['void()'](wrapper)

        # ⭐ 保存引用，防止GC
        self._event_refs.append(wrapper)
        self._event_refs.append(event_cb)

        ns.Simulator.Schedule(ns.Seconds(delay_sec), event_cb)