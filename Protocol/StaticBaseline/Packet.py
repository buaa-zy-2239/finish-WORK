import hashlib
import struct


class StaticBaselinePacket:
    HEADER_STRUCT = struct.Struct(">B32s")

    @staticmethod
    def build(msg_type, pid_hex, payload_bytes, mac_input):
        header = StaticBaselinePacket.HEADER_STRUCT.pack(msg_type, bytes.fromhex(pid_hex))
        mac = bytes.fromhex(hashlib.sha256(mac_input).hexdigest())
        return header + payload_bytes + mac

    @staticmethod
    def parse(packet_bytes):
        header_size = StaticBaselinePacket.HEADER_STRUCT.size
        msg_type, pid_bytes = StaticBaselinePacket.HEADER_STRUCT.unpack(packet_bytes[:header_size])
        mac = packet_bytes[-32:]
        payload = packet_bytes[header_size:-32]
        return msg_type, pid_bytes.hex(), payload, mac.hex()
