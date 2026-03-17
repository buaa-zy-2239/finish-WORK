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
    def bytes_to_pid(pid_bytes: bytes):

        return pid_bytes.hex()


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