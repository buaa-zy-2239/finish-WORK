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
            "ns3::WaypointMobilityModel"
        )

        container = ns.NodeContainer()
        container.Add(self.node)

        helper.Install(container)

        mobility = self.node.GetObject[ns.WaypointMobilityModel]()

        start_x = self.id * 50

        mobility.AddWaypoint(
            ns.Waypoint(
                ns.Seconds(0),
                ns.Vector(start_x, 0, 50)
            )
        )

        mobility.AddWaypoint(
            ns.Waypoint(
                ns.Seconds(30),
                ns.Vector(start_x + 600, 0, 50)
            )
        )

        mobility.AddWaypoint(
            ns.Waypoint(
                ns.Seconds(60),
                ns.Vector(start_x + 1200, 200, 50)
            )
        )

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

        self._safe_schedule(self._mobility_interval, self._mobility_monitor)

        self.ScanZSP()

    def StopApplication(self):

        if self.m_socket:
            self.m_socket.Close()

    # =============================
    # Mobility Monitor
    # =============================

    def _mobility_monitor(self):

        x, y, z = self.GetPosition()

        # print(f"[UAV-{self.id}] pos=({x:.1f},{y:.1f},{z:.1f})")

        self.ScanZSP()

        self._safe_schedule(self._mobility_interval, self._mobility_monitor)

    # =============================
    # RSSI 模型 (Log-distance)
    # =============================

    def GetRSSI(self, node):

        m1 = self.node.GetObject[ns.MobilityModel]()
        m2 = node.GetObject[ns.MobilityModel]()

        dist = m1.GetDistanceFrom(m2)

        if dist < 1:
            dist = 1

        # 参数
        freq = 2.4e9
        c = 3e8

        wavelength = c / freq

        # Friis at 1m
        pr0 = (wavelength / (4 * math.pi)) ** 2

        # path loss exponent
        n = 2.7

        pr = pr0 / (dist ** n)

        rssi_dbm = 10 * math.log10(pr) + 20

        return rssi_dbm

    # =============================
    # ZSP 扫描 + Handover
    # =============================

    def ScanZSP(self):

        best = None
        best_rssi = -999

        for zsp in BaseUAV.ZSP_REGISTRY:

            rssi = self.GetRSSI(zsp.node)

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

        # Handover 判断
        if best_rssi - current_rssi > self.handover_margin:

            print(
                f"[UAV-{self.id}] Handover "
                f"ZSP-{self.current_zsp.zsp_id} → ZSP-{best.zsp_id}"
            )

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

        self.authenticated = False

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

        self._event_refs.append(wrapper)
        self._event_refs.append(event_cb)

        ns.Simulator.Schedule(ns.Seconds(delay_sec), event_cb)