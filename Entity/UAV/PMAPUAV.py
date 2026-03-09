from Entity.UAV.BaseUAV import BaseUAV
from Caculator.ChaoticMap import ChaoticMap
from KeyGen.PUFGenerator import PUFGenerator
from Caculator.Hash import hash_256
import json
import random

class D2D_Session:
    def __init__(self,ni=None,nj=None,ns=None):
        self.ni=ni
        self.nj=nj
        self.ns=ns

class PMAP_UAV(BaseUAV):
    def __init__(self, node, uav_id):
        super().__init__(node, uav_id)
        self.chaotic = ChaoticMap()
        self.puf = PUFGenerator(uav_id)
        self.zsp_id = None
        
        # 安全上下文
        self.crp=[None, None] # (C, R)
        self.new_crp=[None, None] # (C, R)
        self.pid = None
        self.ni = None
        self.ns = None
        self.D2D_sessions = {}
        self.session_key = None

    def StartApplication(self):
        # 初始化：生成初始 R 和 PID (模拟注册阶段已完成)
        self.crp[1] = self.puf.generate_response(self.crp[0])
        self.pid = hash_256(str(self.id) + str(self.crp[1]))
        super().StartApplication()    

    def D2Z_InitiateAuth(self):
        """ [Step 1] 发送认证请求 """
        self.ni = str(random.random())
        
        # 1. 构造明文: PID || ZSP_ID || Ni
        plaintext = f"{self.pid}|{self.zsp_id}|{self.ni}"
        
        # 2. 加密明文
        encrypted_bytes = self.chaotic.encrypt_by_crp(plaintext, self.crp)
        
        # 3. 计算 MAC
        mac = hash_256(encrypted_bytes.hex() + self.ni)
        
        # 4. 发送报文 (M1)
        # 为了让 ZSP 能找到 CRP，实际协议中通常需要传输 PID 的索引或明文 PID
        payload = {
            "type": "M1",
            "pid": self.pid, 
            "m": encrypted_bytes.hex(),
            "mac": mac
        }
        print(f"[UAV-{self.id}] 发送 M1 请求, Ni={self.ni[:6]}...")
        self.SendData(json.dumps(payload))
    
    def D2D_InitiateAuth(self, target_uav_pid):
        """ UAV i 向 UAV j 发起 D2D 认证  """
        session = D2D_Session()
        session.ni = str(random.random())
        self.D2D_sessions[target_uav_pid] = session
        # 构造 M1, M2 明文: PID_i || ZSP_ID || Ni
        plaintext1 = f"{self.pid}|{self.zsp_id}|{session.ni}"
        plaintext2 = f"{self.pid}|{self.zsp_id}|{session.ni}|{target_uav_pid}"
        # 加密 M1,M2 明文
        encrypted_m1 = self.chaotic.encrypt_by_crp(plaintext1, self.crp).hex()
        encrypted_m2 = self.chaotic.encrypt_by_crp(plaintext2, self.crp).hex()
        # 计算 MAC
        mac = hash_256(encrypted_m1 + encrypted_m2 + session.ni + target_uav_pid)
        # 发送 M1 和 M2
        payload = {
            "type": "D2D_M1_M2",
            "m1": encrypted_m1,
            "m2": encrypted_m2,
            "pid": self.pid,
            "mac": mac
        }
        print(f"[UAV-{self.id}] 发送 D2D 认证请求 M1 和 M2.")
        self.SendData(json.dumps(payload))
    
    def Start_D2Z_AuthLater(self, delay=1.0):
        """ 外部调用的便捷接口：延时发起 D2Z 认证 """
        print(f"[Schedule] 计划在 {delay}s 后发起 D2Z 认证...")
        self._safe_schedule(delay, self.D2Z_InitiateAuth)

    def Verify_MAC(self, msgs , params ,mac_from):
        """ 验证 MAC """
        input_str ="".join(msgs) + "".join(params)
        expected_mac = hash_256(input_str)
        return expected_mac == mac_from
    
    def ProcessReceivedData(self, msg_str):
        """ 处理 ZSP 返回的消息 """
        msg = json.loads(msg_str)
        
        # [Step 3] 处理 M2
        if msg.get("type") == "M2":
            m2_bytes = bytes.fromhex(msg["m"])
            
            # 1. 解密
            decrypted_str = self.chaotic.decrypt_by_crp(m2_bytes, self.crp)
            # 明文结构: PID | ZSP | Ni | Ns
            parts = decrypted_str.split('|')
            
            if len(parts) >= 4:
                recv_ni = parts[2]
                self.ns = parts[3]
                
                # 2. 验证 Ni 是否一致 (防重放)
                if recv_ni == self.ni and self.Verify_MAC(msg["m"], [recv_ni,self.ns], msg["mac"]):
                    print(f"[UAV-{self.id}] 验证 ZSP 成功! 收到 Ns={self.ns[:6]}...")
                    
                    # 发送 M3 M4
                    self.ni= str(random.random())
                    new_challenge_seed = self.chaotic.encrypt_by_crp(self.ni + self.ns, self.crp)
                    new_chllenge = int(hash_256(new_challenge_seed.hex()[:13]),16)/(16**13)
                    new_response=self.puf.generate_response(new_chllenge)
                    plantext_m3 = f"{self.pid}|{self.zsp_id}|{self.ns}|{self.ni}"
                    plantext_m4 = f"{self.pid}|{self.zsp_id}|{self.ns}|{self.ni}|{new_response}"
                    encrypted_m3 = self.chaotic.encrypt_by_crp(plantext_m3, self.crp).hex()
                    encrypted_m4 = self.chaotic.encrypt_by_crp(plantext_m4, self.crp).hex()
                    mac=hash_256(f"{encrypted_m3}{encrypted_m4}{self.ni}{str(new_response)}")
                    
                    # 4. 更新 CRP (模拟自愈/更新)
                    payload = {
                        "type": "M3_M4",
                        "m3": encrypted_m3,
                        "m4": encrypted_m4,
                        "pid": self.pid,
                        "mac": mac
                    }
                    print(f"[UAV-{self.id}] 发送 M3 和 M4 确认消息.")
                    self.SendData(json.dumps(payload))
                    # 更新 CRP
                    self.crp=[new_chllenge, new_response]
                    self.pid= hash_256(str(self.id) + str(self.crp[1]))
                    # 3. 生成 Session Key
                    self.session_key = int(hash_256(self.ni),16)^int(hash_256(self.ns),16)
                    print(f"[UAV] 会话密钥建立: {hex(self.session_key)}")
                else:
                    print(f"[UAV-{self.id}] 认证失败: Ni 不匹配")
        elif msg.get("type") == "D2D_M3":
            print(f"[UAV-{self.id}] 收到 D2D 认证请求 M3.")
            m3_bytes = bytes.fromhex(msg["m3"])
            decrypted_str = self.chaotic.decrypt_by_crp(m3_bytes, self.crp)
            parts = decrypted_str.split('|')
            if self.Verify_MAC(msg["m3"], [self.D2D_sessions[parts[2]].ni, parts[4]], msg["mac"]):
                print(f"[UAV-{self.id}] D2D M3 验证通过. Ni={parts[3][:6]}..., N1={parts[4][:6]}...")
                # 这里可以存储 N1 以供后续 D2D 认证使用
                ni = str(random.random())
                self.D2D_sessions[parts[2]].ni = ni
                # 生成 M4,M5
                plaintext_m4 = f"{self.pid}|{self.zsp_id}|{parts[2]}|{parts[4]}|{ni}"
                new_challenge_seed = self.chaotic.encrypt_by_crp(str(ni) + str(parts[4]), self.crp) 
                new_chllenge = int(hash_256(new_challenge_seed.hex()[:13]),16)/(16**13)
                new_response = self.puf.generate_response(new_chllenge)
                self.new_crp = [new_chllenge, new_response]
                plaintext_m5 = f"{self.pid}|{self.zsp_id}|{parts[2]}|{parts[4]}|{ni}|{new_response}"
                encrypted_m4 = self.chaotic.encrypt_by_crp(plaintext_m4, self.crp).hex()
                encrypted_m5 = self.chaotic.encrypt_by_crp(plaintext_m5, self.crp).hex()
                mac = hash_256(f"{encrypted_m4}{encrypted_m5}{ni}{str(new_response)}")
                resp = {
                    "type": "D2D_M4_M5",
                    "m4": encrypted_m4,
                    "m5": encrypted_m5,
                    "pid": self.pid,
                    "mac": mac
                }
                self.SendData(json.dumps(resp))
                print(f"[UAV-{self.id}] 发送 D2D 认证响应 M4 和 M5.")
        
        elif msg.get("type") == "D2D_M6_M7_M8":
            print(f"[UAV-{self.id}] 收到 D2D 认证结果 M6, M7, M8.")
            m6_bytes = bytes.fromhex(msg["m6"])
            m7_bytes = bytes.fromhex(msg["m7"])
            m8_bytes = bytes.fromhex(msg["m8"])
            newpid_i = msg["pid"]
            decrypted_m6 = self.chaotic.decrypt_by_crp(m6_bytes, self.crp)
            decrypted_m7 = self.chaotic.decrypt_by_crp(m7_bytes, self.crp)
            decrypted_m8 = self.chaotic.decrypt_by_crp(m8_bytes, self.crp)
            parts_m6 = decrypted_m6.split('|')
            parts_m7 = decrypted_m7.split('|')
            parts_m8 = decrypted_m8.split('|')
            n2 = parts_m6[2]
            ni = parts_m7[3]
            pid_i = parts_m8[4]
            if self.Verify_MAC([msg["m6"],msg["m7"],msg["m8"]], [n2, ni,pid_i], msg["mac"]):
                print(f"[UAV-{self.id}] D2D 认证成功! N2={parts_m6[2][:6]}..., Ni={parts_m7[3][:6]}...")
                self.D2D_sessions[pid_i] = D2D_Session()
                self.D2D_sessions[pid_i].ni = ni
                self.D2D_sessions[pid_i].nj = str(random.random())
                new_challenge_seed = self.chaotic.encrypt_by_crp(str(n2) + str(self.D2D_sessions[pid_i].nj), self.crp)
                new_chllenge = int(hash_256(new_challenge_seed.hex()[:13]),16)/(16**13)
                new_response = self.puf.generate_response(new_chllenge)
                self.new_crp = [new_chllenge, new_response]
                plaintext_m9 = f"{self.pid}|{self.zsp_id}|{pid_i}|{n2}|{self.D2D_sessions[pid_i].nj}"
                plaintext_m10 = f"{self.pid}|{self.zsp_id}|{pid_i}|{n2}|{self.D2D_sessions[pid_i].nj}|{new_response}"
                encrypted_m9 = self.chaotic.encrypt_by_crp(plaintext_m9, self.crp).hex()
                encrypted_m10 = self.chaotic.encrypt_by_crp(plaintext_m10, self.new_crp).hex()
                mac = hash_256(f"{encrypted_m9}{encrypted_m10}{n2}{self.D2D_sessions[pid_i].nj}{str(new_response)}")
                resp = {
                    "type": "D2D_M9_M10",
                    "m9": encrypted_m9,
                    "m10": encrypted_m10,
                    "pid": self.pid,
                    "mac": mac
                }
                self.SendData(json.dumps(resp))
                # 更新 CRP
                self.crp = self.new_crp
                new_pid = hash_256(str(self.id) + str(self.crp[1]))
                self.pid = new_pid
                print(f"[UAV-{self.id}] CRP 更新成功! 新 PID={self.pid[:6]}...")

                self.D2D_sessions[pid_i].session_key = int(hash_256(ni),16) ^ int(hash_256(self.D2D_sessions[pid_i].nj),16)
                self.D2D_sessions[newpid_i] = self.D2D_sessions.pop(pid_i)  # 更新会话索引为新 PID
                print(f"[UAV-{self.id}] D2D 会话密钥建立: {hex(self.D2D_sessions[newpid_i].session_key)}")
        elif msg.get("type") == "D2D_M11":
            print(f"[UAV-{self.id}] 收到 D2D 认证确认通知 M11.")
            m11_bytes = bytes.fromhex(msg["m11"])
            decrypted_m11 = self.chaotic.decrypt_by_crp(m11_bytes, self.crp).split('|')
            ni = decrypted_m11[3]
            nj = decrypted_m11[4]
            new_pid_j = msg["pid"]
            if self.Verify_MAC(msg["m11"], [decrypted_m11[3], decrypted_m11[4]], msg["mac"]):
                print(f"[UAV-{self.id}] D2D 认证确认! Ni={ni[:6]}..., Nj={nj[:6]}...")
                self.D2D_sessions[decrypted_m11[2]].nj = nj
                self.D2D_sessions[decrypted_m11[2]].session_key = int(hash_256(ni),16) ^ int(hash_256(nj),16)
                self.D2D_sessions[new_pid_j] = self.D2D_sessions.pop(decrypted_m11[2])  # 更新会话索引为新 PID
                print(f"[UAV-{self.id}] D2D 会话密钥确认: {hex(self.D2D_sessions[new_pid_j].session_key)}")
                self.crp = self.new_crp
                self.pid = hash_256(str(self.id) + str(self.crp[1]))


           
            