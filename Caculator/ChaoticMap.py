import math
class ChaoticMap():
    def __init__(self,x_init: float = 0.7):
        """ 初始化混沌生成器 """
        self.a=1.4
        self.b=0.3
        self.x=x_init
    
    def encrypt_by_crp(self,message:str,crp:list[float])->bytes:
        """ 使用混沌映射对消息进行加密 """
        x=crp[0]
        y=crp[1]

        message_bytes=message.encode('utf-8')
        length=len(message_bytes)

        shuffled_bytes=bytearray(length)
        used_index=[False]*length

        for i in range(length):
            new_x=1 - self.a * x * x + y
            new_y=self.b * x

            if math.isinf(new_x) or math.isnan(new_x) or abs(new_x) > 1e10:
                 new_x = 0.1
            if math.isinf(new_y) or math.isnan(new_y) or abs(new_y) > 1e10:
                 new_y = 0.1

            mod_base=length
            raw_val=(new_x * 10) + (new_y * 10)
            index=(int(abs(raw_val))) % mod_base

            # 线性探测
            while True:
                if not used_index[index]:
                    shuffled_bytes[index]=message_bytes[i]
                    used_index[index]=True
                    break
                else:
                    index+=1
                    if index>=length:
                        index=0

            x=new_x
            y=new_y

        return bytes(shuffled_bytes)
    
    def decrypt_by_crp(self,encrypted_message:bytes,crp:list[float])->str:
        """ 使用混沌映射对消息进行解密 """
        x=crp[0]
        y=crp[1]
        length=len(encrypted_message)
        unshuffled_bytes=bytearray(length)
        used_index=[False]*length
        for i in range(length):
            new_x=1 - self.a * x * x + y
            new_y=self.b * x

            # --- 新增：数值溢出保护 (必须与 encrypt 保持一致) ---
            if math.isinf(new_x) or math.isnan(new_x) or abs(new_x) > 1e10:
                new_x = 0.1
            if math.isinf(new_y) or math.isnan(new_y) or abs(new_y) > 1e10:
                new_y = 0.1
            # ------------------------------------------------

            mod_base=length
            raw_val=(new_x * 10) + (new_y * 10)
            index=(int(abs(raw_val))) % mod_base

            # 线性探测
            while True:
                if not used_index[index]:
                    unshuffled_bytes[i]=encrypted_message[index]
                    used_index[index]=True
                    break
                else:
                    index+=1
                    if index>=length:
                        index=0

            x=new_x
            y=new_y

        return unshuffled_bytes.decode('utf-8')