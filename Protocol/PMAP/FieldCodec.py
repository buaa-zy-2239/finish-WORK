import struct

class FieldCodec:

    DOUBLE = struct.Struct(">d")
    UINT32 = struct.Struct(">I")

    @staticmethod
    def encode_pid(pid_hex: str):

        return bytes.fromhex(pid_hex)


    @staticmethod
    def decode_pid(data: bytes):

        return data.hex()


    @staticmethod
    def encode_double(value: float):

        return FieldCodec.DOUBLE.pack(value)


    @staticmethod
    def decode_double(data: bytes):

        return FieldCodec.DOUBLE.unpack(data)[0]


    @staticmethod
    def encode_uint32(v: int):

        return FieldCodec.UINT32.pack(v)


    @staticmethod
    def decode_uint32(data: bytes):

        return FieldCodec.UINT32.unpack(data)[0]