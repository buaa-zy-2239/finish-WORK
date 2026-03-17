import struct

class BinaryCodec:

    HEADER = struct.Struct(">BH")

    @staticmethod
    def pack(msg_type: int, payload: bytes):

        header = BinaryCodec.HEADER.pack(
            msg_type,
            len(payload)
        )

        return header + payload


    @staticmethod
    def unpack(packet: bytes):

        msg_type, length = BinaryCodec.HEADER.unpack(packet[:3])

        payload = packet[3:3+length]

        return msg_type, payload