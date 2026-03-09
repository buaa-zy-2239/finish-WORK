from ns import ns
import abc
import cppyy
import ctypes

class BaseUAV(ns.Application):
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

        self._install_mobility()
        # ---- 新增：用于轮询调度的保活引用 ----
        self._poll_cb_refs = []
        self._poll_wrapper_refs = []
        self._poll_interval = ns.MilliSeconds(1)

        # 专门用来存放延时任务的闭包，防止被 Python GC 回收导致 SegFault
        self._pending_events = []
        self.authenticated = False

    # =============================
    # Application 生命周期
    # =============================

    def StartApplication(self):
        # 绑定随机端口
        self.m_socket.Bind()

        print(f"[UAV-{self.id}] Application Started (Polling Mode)")
        self._schedule_poll()

    def StopApplication(self):
        # 可选：停止时清理 socket
        if self.m_socket:
            self.m_socket.Close()

    # =============================
    # Python 版 RecvCallback（核心）
    # =============================

    def _schedule_poll(self):
        """
        调度一次轮询事件（等价于“注册 RecvCallback”）
        """
        cb = lambda: self._poll_socket()
        wrapper = cppyy.gbl.std.function['void()'](cb)

        # ---- 关键：双重保活 ----
        self._poll_cb_refs.append(cb)
        self._poll_wrapper_refs.append(wrapper)

        ns.Simulator.Schedule(self._poll_interval, wrapper)

    def _poll_socket(self):
        """
        安全的 Polling 实现（不会卡死）
        """
        handled_any = False
        while self.m_socket.GetRxAvailable() > 0:
            handled_any = True
            from_addr=ns.Address()
            packet = self.m_socket.RecvFrom(from_addr)
            if not packet or packet.GetSize() == 0:
                print("packet is none")
                break

            size = packet.GetSize()
            buf = bytearray(size)
            packet.CopyData(buf, size)

            try:
                msg = buf.decode("utf-8")
                self.ProcessReceivedData(msg)
            except UnicodeDecodeError:
                print(f"[ZSP-{self.zsp_id}] Decode Error")

        # ⚠️ 关键区别在这里
        # 只有“本轮没有处理任何数据”才延后轮询
        self._schedule_poll()

    # =============================
    # 连接与发送
    # =============================

    def Connect(self, zsp_address, zsp_port=9999):
        inet_addr = ns.InetSocketAddress(zsp_address, zsp_port)
        final_addr = inet_addr.ConvertTo()
        self.m_socket.Connect(final_addr)

        print(f"[DEBUG] UAV-{self.id} 成功连接至 {zsp_address}:{zsp_port}")

    def SendData(self, payload_str):
        if self.m_socket is None:
            return

        # 1. 编码数据
        data_bytes = payload_str.encode('utf-8')
        
        import cppyy
        
        # 手动申请一段 C++ 内存块
        size = len(data_bytes)
        cpp_buffer = cppyy.gbl.std.vector['uint8_t'](size)
        for i in range(size):
            cpp_buffer[i] = data_bytes[i]

        try:
            packet = ns.Packet(cpp_buffer.data(), size)
        except:
            packet = ns.Packet(list(data_bytes)) # 确保 list 里的元素是 int
        
        if packet.GetSize() > 0:
            print(f"[DEBUG] Packet created with size: {packet.GetSize()}")
        self.m_socket.Send(packet)

        # =============================
        # 协议逻辑（由子类实现）
        # =============================

    @abc.abstractmethod
    def ProcessReceivedData(self, msg_str):
        """
        [抽象方法]
        处理接收到的字符串数据
        """
        pass

    def _safe_schedule(self, delay_sec, func, *args):
        """
        参考 _schedule_poll 实现的通用安全调度器
        :param delay_sec: 延迟时间（秒）
        :param func: 要执行的函数
        :param args: 函数参数
        """
        import cppyy
        from ns import ns

        # 1. 定义包装函数，模仿 _schedule_poll 的闭包逻辑
        def wrapper():
            # 执行目标业务逻辑
            func(*args)
            if wrapper in self._poll_wrapper_refs:
                self._poll_wrapper_refs.remove(wrapper)

        try:
            event_cb = cppyy.gbl.std.function['void()'](wrapper)
            
            # 3. 将包装器存入父类的保活列表，防止 GC 导致 SegFault
            self._poll_wrapper_refs.append(wrapper)
            self._poll_wrapper_refs.append(event_cb) # 双重保活

            # 4. 提交调度到 ns-3 模拟器
            ns.Simulator.Schedule(ns.Seconds(delay_sec), event_cb)
            
        except Exception as e:
            print(f"[Error] _safe_schedule 调度失败: {e}")
    
