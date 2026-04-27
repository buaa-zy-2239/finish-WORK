import struct


class RLBAPlaintext:
    # 三方认证消息结构
    USER_REQUEST = struct.Struct(">32sddd32s")  # user_id, rn1, ts1, uav_id, auth_u
    GSS_TO_UAV = struct.Struct(">32s32sddd32s")  # gss_id, user_id, rn1, rn2, ts2, auth_g
    UAV_TO_GSS = struct.Struct(">32s32s32sddd32s32s")  # uav_id, gss_id, user_id, rn2, rn3, ts3, auth_d, auth_gss
    GSS_TO_USER = struct.Struct(">32s32sddd32s32s")  # gss_id, user_id, rn3, rn4, ts4, auth_g, auth_gu
    USER_CONFIRM = struct.Struct(">32s32sddd32s")  # user_id, gss_id, rn4, rn5, ts5, auth_u
    SUCCESS = struct.Struct(">32s32s32s32s32s")  # gss_id, user_id, uav_id, session_key_ug, session_key_ud

    @staticmethod
    def pid_bytes(pid_hex: str) -> bytes:
        return bytes.fromhex(pid_hex)
