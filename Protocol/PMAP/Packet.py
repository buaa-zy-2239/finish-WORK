import struct
import hashlib

class PMAPPacket:

    HEADER_STRUCT = struct.Struct(">B32s")

    @staticmethod
    def build(msg_type, pid_hex, payload_bytes, mac_input):

        pid_bytes = bytes.fromhex(pid_hex)

        header = PMAPPacket.HEADER_STRUCT.pack(
            msg_type,
            pid_bytes
        )

        mac = bytes.fromhex(hashlib.sha256(mac_input).hexdigest())
        return header + payload_bytes + mac


    @staticmethod
    def parse(packet_bytes):

        header_size = PMAPPacket.HEADER_STRUCT.size

        msg_type, pid_bytes = PMAPPacket.HEADER_STRUCT.unpack(
            packet_bytes[:header_size]
        )

        mac = packet_bytes[-32:]

        payload = packet_bytes[header_size:-32]

        return msg_type, pid_bytes.hex(), payload, mac.hex()