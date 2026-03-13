from Entity.ZSP.BaseZSP import BaseZSP
from Caculator.ChaoticMap import ChaoticMap
from Caculator.Hash import hash_256
import json
import random

class D2Z_Session:
    def __init__(self):
        self.ni = None
        self.ns = None
        self.from_addr = None
        self.session_key = None
    
class D2D_Session:
    def __init__(self,ni=None,nj=None,n1=None,n2=None,from_addr=None,to_addr=None):
        self.ni=ni
        self.nj=nj
        self.n1=n1
        self.n2=n2
        self.from_addr=from_addr
        self.to_addr=to_addr

class PMAP_ZSP(BaseZSP):
    def __init__(self, node, zsp_id, blockchain=None, enable_blockchain=True):
        super().__init__(node, zsp_id, blockchain=blockchain, enable_blockchain=enable_blockchain)
        self.chaotic = ChaoticMap()
        self.D2Z_sessions = {}
        self.D2D_sessions = {}
        self.ni = None
        self.ns = None
        self.n1 = None
        self.n2 = None
        self.crp = [None, None]  # (C, R)

    def HandleRead(self, socket):
        """ 接收回调：处理来自 UAV 的请求 """
        # 使用 RecvFrom 获取发送方地址
        packet, from_addr = socket.RecvFrom()
        if not packet or packet.GetSize() == 0:
            return

        data_size = packet.GetSize()
        data = bytearray(data_size)
        packet.CopyData(data, data_size)

        try:
            msg_str = data.decode('utf-8')
            self.ProcessRequest(msg_str, from_addr)
        except UnicodeDecodeError:
            print(f"[ZSP-{self.zsp_id}] Decode Error")
            
    def Verify_MAC(self, msgs, params ,mac_from):
        """ 验证 MAC """
        input_str ="".join(msgs) + "".join(params)
        expected_mac = hash_256(input_str)
        return expected_mac == mac_from

    def RegisterUAV(self, pid, uav_data):
        """ 预注册 UAV 信息 """
        self.uav_db[pid] = uav_data
        if self.enable_blockchain:
            self.blockchain.register_uav(pid)
            print('Register PID is '+pid)

    def ProcessRequest(self, msg_str, from_addr):
        """ [Step 2 & 4] 处理 UAV 消息 """
        try:
            msg = json.loads(msg_str)
        except json.JSONDecodeError as e:
            print(f"[ZSP-{self.zsp_id} Error] JSON Parse Failed: {e}")
            print(f"[ZSP-{self.zsp_id} Debug] Raw Data (first 50 chars): {msg_str[:50]!r}") # 使用 !r 查看是否有隐藏字符
            return
        except Exception as e:
            print(f"[ZSP-{self.zsp_id} Error] Unknown Error: {e}")
            return
        # 处理 M1 请求
        if msg.get("type") == "M1":
            pid = msg.get("pid")
            if self.enable_blockchain:
                if not self.blockchain.is_valid_uav(pid):
                    print(f"[ZSP-{self.zsp_id}] Blockchain 拒绝: 未知 PID {pid}")
                    return
            elif pid not in self.uav_db:
                print(f"[ZSP-{self.zsp_id}] 拒绝: 未知 PID {pid}")
                return
            uav_data = self.uav_db[pid]
            crp_params = uav_data["crp"] # 对应 UAV 的参数
            self.D2Z_sessions[pid] = D2Z_Session() # 初始化会话状态
            self.D2Z_sessions[pid].from_addr = from_addr

            # 1. 解密 M1
            m1_bytes = bytes.fromhex(msg["m"])
            decrypted = self.chaotic.decrypt_by_crp(m1_bytes, crp_params)
            # 结构: PID | ZSP | Ni
            parts = decrypted.split('|')
            if len(parts) >= 3 and self.Verify_MAC(msg["m"], [parts[2]], msg["mac"]):
                ni = parts[2]
                print(f"[ZSP-{self.zsp_id}] M1 验证通过. UAV={uav_data['uav_id']}, Ni={ni[:6]}...")
                
                # 2. 生成 Ns 并构造 M2
                ns = str(random.random())
                # 构造 M2 明文: PID | ZSP | Ni | Ns
                plaintext_m2 = f"{pid}|{self.zsp_id}|{ni}|{ns}"
                
                encrypted_m2 = self.chaotic.encrypt_by_crp(plaintext_m2, crp_params)
                
                mac= hash_256(encrypted_m2.hex() + ni + ns)
                # 3. 发送 M2
                resp = {
                    "type": "M2",
                    "m": encrypted_m2.hex(),
                    "mac": mac
                }
                self.SendResponse(json.dumps(resp), from_addr)
                
                # 保存会话状态 (为了生成 Session Key)
                self.D2Z_sessions[pid].ns = ns

        # 处理 M3 确认
        elif msg.get("type") == "M3_M4":
            pid = msg.get("pid")
            if self.enable_blockchain:
                if not self.blockchain.is_valid_uav(pid):
                    print(f"[ZSP-{self.zsp_id}] 拒绝: 未知 PID {pid}")
                    return
            elif pid not in self.uav_db:
                print(f"[ZSP-{self.zsp_id}] 拒绝: 未知 PID {pid}")
                return
            
            uav_data = self.uav_db[pid]
            crp_params = uav_data["crp"]
            
            m3_bytes = bytes.fromhex(msg["m3"])
            m4_bytes = bytes.fromhex(msg["m4"])
            decrypted_m3 = self.chaotic.decrypt_by_crp(m3_bytes, crp_params)
            decrypted_m4 = self.chaotic.decrypt_by_crp(m4_bytes, crp_params)
            messages = [decrypted_m3, decrypted_m4]
            parts1 = messages[0].split('|')
            parts2 = messages[1].split('|')
            if self.Verify_MAC([msg["m3"], msg["m4"]], [parts1[3], parts2[4]], msg["mac"]):
                print(f"[ZSP-{self.zsp_id}] M3/M4 验证通过. UAV={uav_data['uav_id']}, Ni={parts1[3][:6]}...")
                self.D2Z_sessions[pid].ni = parts1[3]
                new_challenge_seed = self.chaotic.encrypt_by_crp(self.D2Z_sessions[pid].ni + self.D2Z_sessions[pid].ns, crp_params)
                crp_params[0] = int(hash_256(new_challenge_seed.hex()[:13]),16)/(16**13)
                crp_params[1] = float(parts2[4])
                uav_data["crp"] = crp_params
                new_pid = hash_256(str(uav_data['uav_id']) + str(crp_params[1]))
                self.UpdateUAVPID(pid, new_pid,crp_params[0],crp_params[1])
                print(f"[ZSP-{self.zsp_id}] UAV 新 PID 更新: {new_pid[:6]}...")
                # 生成 Session Key
                self.D2Z_sessions[new_pid] = self.D2Z_sessions.pop(pid) # 迁移会话状态到新 PID
                self.D2Z_sessions[new_pid].session_key = int(hash_256(self.D2Z_sessions[new_pid].ni),16)^int(hash_256(self.D2Z_sessions[new_pid].ns),16)
                print(f"[ZSP-{self.zsp_id}] 会话密钥建立: {hex(self.D2Z_sessions[new_pid].session_key)}")
                if self.enable_blockchain:
                    self.blockchain.record_auth_event(pid, True)
                    
        elif msg.get("type") == "D2D_M1_M2":
            print(f"[ZSP-{self.zsp_id}] 收到 D2D 认证请求 M1 和 M2.")
            pid = msg.get("pid")
            if self.enable_blockchain:
                if not self.blockchain.is_valid_uav(pid):
                    print(f"[ZSP-{self.zsp_id}] Blockchain 拒绝: 未知 PID {pid}")
                    return
            elif pid not in self.uav_db:
                print(f"[ZSP-{self.zsp_id}] 拒绝: 未知 PID {pid}")
                return
            
            uav_data = self.uav_db[pid]
            crp_params = uav_data["crp"]
            self.crp = crp_params # 更新当前 CRP 以供后续加解密使用
            
            m1_bytes = bytes.fromhex(msg["m1"])
            m2_bytes = bytes.fromhex(msg["m2"])
            
            decrypted_m1 = self.chaotic.decrypt_by_crp(m1_bytes, crp_params)
            decrypted_m2 = self.chaotic.decrypt_by_crp(m2_bytes, crp_params)
            
            parts1 = decrypted_m1.split('|')
            parts2 = decrypted_m2.split('|')
            pid_j = parts2[3]
            ni = parts1[2]
            
            if self.Verify_MAC([msg["m1"], msg["m2"]], [str(ni), str(pid_j)], msg["mac"]):
                print(f"[ZSP-{self.zsp_id}] D2D M1/M2 验证通过. UAV={uav_data['uav_id']}, Ni={parts1[2][:6]}..., Nj={parts2[2][:6]}...")
                # 这里可以存储 Nj 以供后续 D2D 认证使用
                self.D2D_sessions[pid] = D2D_Session(ni=ni,nj=None,n1=str(random.random()),n2=str(random.random()),
                                        from_addr=from_addr,to_addr=self.D2Z_sessions[pid_j].from_addr)
                # 生成 M3
                plaintext_m3 = f"{pid}|{self.zsp_id}|{parts2[3]}|{self.D2D_sessions[pid].ni}|{self.D2D_sessions[pid].n1}"
                encrypted_m3 = self.chaotic.encrypt_by_crp(plaintext_m3, crp_params)
                mac = hash_256(f"{encrypted_m3.hex()}{self.D2D_sessions[pid].ni}{self.D2D_sessions[pid].n1}")
                resp = {
                    "type": "D2D_M3",
                    "m3": encrypted_m3.hex(),
                    "mac": mac
                }
                self.SendResponse(json.dumps(resp), from_addr)
        elif msg.get("type") == "D2D_M4_M5":
            print(f"[ZSP-{self.zsp_id}] 收到 D2D 认证请求 M4 和 M5.")
            pid = msg.get("pid")
            if self.enable_blockchain:
                if not self.blockchain.is_valid_uav(pid):
                    print(f"[ZSP-{self.zsp_id}] 拒绝: 未知 PID {pid}")
                    return
            elif pid not in self.uav_db:
                print(f"[ZSP-{self.zsp_id}] 拒绝: 未知 PID {pid}")
                return
            
            uav_data = self.uav_db[pid]
            crp_params = uav_data["crp"]
            
            m4_bytes = bytes.fromhex(msg["m4"])
            m5_bytes = bytes.fromhex(msg["m5"])
            
            decrypted_m4 = self.chaotic.decrypt_by_crp(m4_bytes, crp_params)
            decrypted_m5 = self.chaotic.decrypt_by_crp(m5_bytes, crp_params)
            
            parts4 = decrypted_m4.split('|')
            parts5 = decrypted_m5.split('|')
            ni = parts4[4]
            new_response = parts5[5]
            pid_j = parts4[2]
            new_pid = hash_256(str(uav_data['uav_id']) + str(new_response))
            
            if self.Verify_MAC([msg["m4"], msg["m5"]], [ni, new_response], msg["mac"]):
                print(f"[ZSP-{self.zsp_id}] D2D M4/M5 验证通过. UAV={uav_data['uav_id']}, Ni={ni[:6]}..., new_response={new_response[:6]}...")
                # 这里可以存储 N1 以供后续 D2D 认证使用
                self.D2D_sessions[pid].ni = ni
                plaintext_m6 =  f"{pid_j}|{self.zsp_id}|{self.D2D_sessions[pid].n2}"
                plaintext_m7 = f"{pid_j}|{self.zsp_id}|{self.D2D_sessions[pid].n2}|{ni}"
                plaintext_m8 = f"{pid_j}|{self.zsp_id}|{self.D2D_sessions[pid].n2}|{ni}|{pid}"
                crp_params = self.uav_db[pid_j]["crp"]
                encrypted_m6 = self.chaotic.encrypt_by_crp(plaintext_m6, crp_params)
                encrypted_m7 = self.chaotic.encrypt_by_crp(plaintext_m7, crp_params)
                encrypted_m8 = self.chaotic.encrypt_by_crp(plaintext_m8, crp_params)
                mac = hash_256(f"{encrypted_m6.hex()}{encrypted_m7.hex()}{encrypted_m8.hex()}{self.D2D_sessions[pid].n2}{ni}{pid}")
                resp = {
                    "type": "D2D_M6_M7_M8",
                    "m6": encrypted_m6.hex(),
                    "m7": encrypted_m7.hex(),
                    "m8": encrypted_m8.hex(),
                    "pid" : new_pid,
                    "mac": mac
                }
                self.SendResponse(json.dumps(resp), self.D2D_sessions[pid].to_addr)
                print(f"[ZSP-{self.zsp_id}] 发送 D2D 认证响应 M6、M7 和 M8.")
                # 更新 CRP
                crp_params = self.uav_db[pid]["crp"]
                new_challenge_seed = self.chaotic.encrypt_by_crp(self.D2D_sessions[pid].n1 + ni, crp_params)
                self.uav_db[pid]["crp"][0] = int(hash_256(new_challenge_seed.hex()[:13]),16)/(16**13)
                self.uav_db[pid]["crp"][1] = float(new_response)
                self.UpdateUAVPID(pid,new_pid,self.uav_db[pid]["crp"][0],self.uav_db[pid]["crp"][1])
                print(f"[ZSP] UAV 新 PID 更新: {new_pid[:6]}...")
        elif msg.get("type") == "D2D_M9_M10":
            print(f"[ZSP-{self.zsp_id}] 收到 D2D 认证请求 M9 和 M10.")
            pid = msg.get("pid")
            if self.enable_blockchain:
                if not self.blockchain.is_valid_uav(pid):
                    print(f"[ZSP-{self.zsp_id}] 拒绝: 未知 PID {pid}")
                    return
            elif pid not in self.uav_db:
                print(f"[ZSP-{self.zsp_id}] 拒绝: 未知 PID {pid}")
                return
            
            uav_data = self.uav_db[pid]
            crp_params = uav_data["crp"]
            
            m9_bytes = bytes.fromhex(msg["m9"])
            m10_bytes = bytes.fromhex(msg["m10"])
            
            decrypted_m9 = self.chaotic.decrypt_by_crp(m9_bytes, crp_params)
            decrypted_m10 = self.chaotic.decrypt_by_crp(m10_bytes, crp_params)
            
            parts9 = decrypted_m9.split('|')
            parts10 = decrypted_m10.split('|')
            pid_i = parts9[2]
            n2 = parts9[3]
            nj = parts9[4]
            new_response = parts10[5]
            new_pid = hash_256(str(uav_data['uav_id']) + str(new_response))
            if self.Verify_MAC([msg["m9"], msg["m10"]], [n2,nj, new_response], msg["mac"]):
                print(f"[ZSP-{self.zsp_id}] D2D M9/M10 验证通过. UAV={uav_data['uav_id']}, Nj={nj[:6]}..., new_response={new_response[:6]}...")
                # 这里可以存储 N1 以供后续 D2D 认证使用

                plaintext_m11 = f"{pid_i}|{self.zsp_id}|{pid}|{self.D2D_sessions[pid_i].ni}|{nj}"
                crp_params = self.crp
                encrypted_m11 = self.chaotic.encrypt_by_crp(plaintext_m11, crp_params)
                mac = hash_256(f"{encrypted_m11.hex()}{self.D2D_sessions[pid_i].ni}{nj}")
                resp = {
                    "type": "D2D_M11",
                    "m11": encrypted_m11.hex(),
                    "pid": new_pid,
                    "mac": mac
                }
                self.SendResponse(json.dumps(resp), self.D2D_sessions[pid_i].from_addr)
                print(f"[ZSP-{self.zsp_id}] 发送 D2D 认证响应 M11.")
                # 更新 CRP
                crp_params = self.uav_db[pid]["crp"]
                new_challenge_seed = self.chaotic.encrypt_by_crp(str(nj) + str(self.D2D_sessions[pid_i].n2), crp_params)
                self.uav_db[pid]["crp"][0] = int(hash_256(new_challenge_seed.hex()[:13]),16)/(16**13)
                self.uav_db[pid]["crp"][1] = float(new_response)
                
                self.UpdateUAVPID(pid,new_pid,self.uav_db[pid]["crp"][0],self.uav_db[pid]["crp"][1])
                print(f"[ZSP-{self.zsp_id}] UAV 新 PID 更新: {new_pid[:6]}...")
                session_key = int(hash_256(nj),16)^int(hash_256(self.D2D_sessions[pid_i].ni),16)
                print(f"[ZSP-{self.zsp_id}] D2D 会话密钥建立: {hex(session_key)}")
