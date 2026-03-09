from ns import ns
import cppyy
import abc
from BlockChain.Blockchain import Web3BlockchainAdapter

class BaseZSP(ns.Application):
    def __init__(self, node, zsp_id, enable_blockchain=False):
        super().__init__()
        self.node = node
        self.zsp_id = zsp_id

        self.m_socket = ns.Socket.CreateSocket(
            self.node,
            ns.TypeId.LookupByName("ns3::UdpSocketFactory")
        )

        # 数据库：存储 {PID: {RealID, CRP, ...}}
        self.enable_blockchain=enable_blockchain
        if self.enable_blockchain:
            self.blockchain=Web3BlockchainAdapter()
        self.uav_db = {}

        # ---- 新增：轮询调度相关 ----
        self._poll_cb_refs = []
        self._poll_wrapper_refs = []
        self._poll_interval = ns.MilliSeconds(1)

        self.m_socket.SetAllowBroadcast(True)
    # =============================
    # Application 生命周期
    # =============================

    def StartApplication(self):
        local_address = ns.InetSocketAddress(
            ns.Ipv4Address.GetAny(), 9999
        )
        self.m_socket.Bind(local_address.ConvertTo())

        print(f"[ZSP-{self.zsp_id}] Service Started on Port 9999 (Polling Mode)")

        # 启动“模拟 RecvCallback”的轮询服务
        self._schedule_poll()

    def StopApplication(self):
        if self.m_socket:
            self.m_socket.Close()

    # =============================
    # Python 版 RecvCallback（核心）
    # =============================

    def _schedule_poll(self):
        """
        调度一次 Socket 轮询事件
        （功能等价于 SetRecvCallback）
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
            print("Receive!")
            size = packet.GetSize()
            buf = bytearray(size)
            packet.CopyData(buf, size)

            try:
                msg = buf.decode("utf-8")
                self.ProcessRequest(msg, from_addr)
            except UnicodeDecodeError:
                print(f"[ZSP-{self.zsp_id}] Decode Error")

        # ⚠️ 关键区别在这里
        # 只有“本轮没有处理任何数据”才延后轮询
        self._schedule_poll()


    # =============================
    # 发送接口
    # =============================

    def SendResponse(self, payload_str, dest_addr):
        """
        向指定地址回复数据
        """
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

        self.m_socket.SendTo(packet, 0, dest_addr)

    # =============================
    # 协议逻辑（子类实现）
    # =============================

    @abc.abstractmethod
    def ProcessRequest(self, msg_str, from_addr):
        """
        [抽象方法]
        处理来自 UAV 的请求
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
    
    