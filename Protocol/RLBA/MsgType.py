class RLBAMessageType:
    # 三方认证消息类型
    USER_REQUEST = 1      # 用户到GSS的认证请求
    GSS_TO_UAV = 2        # GSS到UAV的认证请求
    UAV_TO_GSS = 3        # UAV到GSS的认证响应
    GSS_TO_USER = 4       # GSS到用户的认证响应
    USER_CONFIRM = 5      # 用户到GSS的最终确认
    SUCCESS = 6           # 认证成功消息
