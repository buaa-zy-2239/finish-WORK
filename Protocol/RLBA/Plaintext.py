import struct


class RLBAPlaintext:
    M1 = struct.Struct(">32sddd32s")
    M2 = struct.Struct(">32s32sddd32s")
    M3 = struct.Struct(">32s32sddd32s32s")
    SUCCESS = struct.Struct(">32s32s32s")

    @staticmethod
    def pid_bytes(pid_hex: str) -> bytes:
        return bytes.fromhex(pid_hex)
