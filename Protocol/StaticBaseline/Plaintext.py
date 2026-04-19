import struct


class StaticBaselinePlaintext:
    M1 = struct.Struct(">32sId")
    M2 = struct.Struct(">32sIdd")
    M3 = struct.Struct(">32sIdd32s")

    @staticmethod
    def pid_bytes(pid_hex: str) -> bytes:
        return bytes.fromhex(pid_hex)
