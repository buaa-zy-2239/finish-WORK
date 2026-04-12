import struct


class PMAPPlaintext:
    """
    All PMAP plaintext structures (D2Z + D2D)
    Network byte order: big-endian
    """

    PID_SIZE = 32

    # =========================================================
    # D2Z STRUCTURES
    # =========================================================

    # M1
    # PID | ZSP_ID | Ni
    M1 = struct.Struct(">32sId")

    # M2
    # PID | ZSP_ID | Ni | Ns
    M2 = struct.Struct(">32sIdd")

    #M3
    # PID | ZSP_ID | Ns | Ni
    M3 = struct.Struct(">32sIdd")
    #M4
    # PID | ZSP_ID | Ns | Ni | Response
    M4 = struct.Struct(">32sIddd")

    # D2Z ACK（密文用当前 CRP 加密）：旧 PID | 新 PID | challenge | response
    # 明文含轮换前后 PID，机端可与 pending/self.pid 绑定，避免仅依赖报文头 PID。
    D2Z_ACK = struct.Struct(">32s32sdd")

    # =========================================================
    # D2D STRUCTURES
    # =========================================================

    # D2D M1
    # PID_i | ZSP_ID | Ni
    D2D_M1 = struct.Struct(">32sId")

    # D2D M2
    # PID_i | ZSP_ID | Ni | PID_j
    D2D_M2 = struct.Struct(">32sId32s")

    # D2D M3
    # PID_i | ZSP_ID | PID_j | Ni | N1
    D2D_M3 = struct.Struct(">32sI32sdd")

    # D2D M4
    # PID_j | ZSP_ID | PID_i | N1 | Nj
    D2D_M4 = struct.Struct(">32sI32sdd")

    # D2D M5
    # PID_j | ZSP_ID | PID_i | N1 | Nj | Response
    D2D_M5 = struct.Struct(">32sI32sddd")

    # D2D M6
    # PID_i | ZSP_ID | N2
    D2D_M6 = struct.Struct(">32sId")

    # D2D M7
    # PID_i | ZSP_ID | N2 | Ni
    D2D_M7 = struct.Struct(">32sIdd")

    # D2D M8
    # PID_i | ZSP_ID | N2 | Ni | PID_j
    D2D_M8 = struct.Struct(">32sIdd32s")

    # D2D M9
    # PID_j | ZSP_ID | PID_i | N2 | Nj
    D2D_M9 = struct.Struct(">32sI32sdd")

    # D2D M10
    # PID_j | ZSP_ID | PID_i | N2 | Nj | Response
    D2D_M10 = struct.Struct(">32sI32sddd")

    # D2D M11
    # PID_j | ZSP_ID | PID_i | Ni | Nj
    D2D_M11 = struct.Struct(">32sI32sdd")


    # =========================================================
    # Helper
    # =========================================================

    @staticmethod
    def pid_to_bytes(pid_hex: str):

        return bytes.fromhex(pid_hex)


    @staticmethod
    def bytes_to_pid(pid_field):
        """decode() 已将 32 字节 PID 转为 hex 字符串；此处同时兼容原始 bytes。"""
        if isinstance(pid_field, str):
            return pid_field
        if isinstance(pid_field, (bytes, bytearray)):
            return bytes(pid_field).hex()
        raise TypeError(f"PID field must be str or bytes, got {type(pid_field)}")


    # =========================================================
    # Generic encode
    # =========================================================

    @staticmethod
    def encode(struct_obj, *fields):

        processed = []

        for f in fields:

            if isinstance(f, str) and len(f) == 64:
                processed.append(bytes.fromhex(f))
            else:
                processed.append(f)

        return struct_obj.pack(*processed)


    # =========================================================
    # Generic decode
    # =========================================================

    @staticmethod
    def decode(struct_obj, data):

        values = list(struct_obj.unpack(data))

        for i, v in enumerate(values):

            if isinstance(v, bytes) and len(v) == PMAPPlaintext.PID_SIZE:
                values[i] = v.hex()

        return tuple(values)