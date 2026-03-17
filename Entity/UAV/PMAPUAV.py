from Entity.UAV.BaseUAV import BaseUAV
from Caculator.ChaoticMap import ChaoticMap
from KeyGen.PUFGenerator import PUFGenerator
from Caculator.Hash import hash_256

from Protocol.PMAP.PMAPPlaintext import PMAPPlaintext
from Protocol.PMAP.Packet import PMAPPacket
from Protocol.PMAP.MsgType import PMAPMessageType

import random
import struct


class D2D_Session:

    def __init__(self):
        self.ni = None
        self.nj = None
        self.n2 = None
        self.session_key = None


class PMAP_UAV(BaseUAV):

    def __init__(self, node, uav_id):

        super().__init__(node, uav_id)

        self.chaotic = ChaoticMap()
        self.puf = PUFGenerator(uav_id)

        self.zsp_id = None

        # CRP
        self.crp = [None, None]
        self.new_crp = [None, None]

        self.pid = None

        # D2Z
        self.ni = None
        self.ns = None

        self.session_key = None

        # D2D sessions
        self.D2D_sessions = {}


    # =========================================================
    # Initialization
    # =========================================================

    def StartApplication(self):

        self.crp[1] = self.puf.generate_response(self.crp[0])

        self.pid = hash_256(str(self.id) + str(self.crp[1]))

        super().StartApplication()


    # =========================================================
    # D2Z Initiate (M1)
    # =========================================================

    def D2Z_InitiateAuth(self):

        self.ni = random.random()
        plaintext = PMAPPlaintext.encode(
            PMAPPlaintext.M1,
            self.pid,
            self.zsp_id,
            self.ni
        )
        
        encrypted = self.chaotic.encrypt_by_crp(
            plaintext,
            self.crp
        )
        mac_input = encrypted + struct.pack(">d", self.ni)
        packet = PMAPPacket.build(
            PMAPMessageType.M1,
            self.pid,
            encrypted,
            mac_input
        )
        
        print(f"[UAV-{self.id}] Send M1")

        self.SendData(packet)


    # =========================================================
    # D2D Initiate (M1 M2)
    # =========================================================

    def D2D_InitiateAuth(self, target_pid):

        session = D2D_Session()

        session.ni = random.random()

        self.D2D_sessions[target_pid] = session

        m1_plain = PMAPPlaintext.encode(
            PMAPPlaintext.D2D_M1,
            self.pid,
            self.zsp_id,
            session.ni
        )

        m2_plain = PMAPPlaintext.encode(
            PMAPPlaintext.D2D_M2,
            self.pid,
            self.zsp_id,
            session.ni,
            target_pid
        )

        enc1 = self.chaotic.encrypt_by_crp(m1_plain, self.crp)
        enc2 = self.chaotic.encrypt_by_crp(m2_plain, self.crp)

        payload = enc1 + enc2

        mac_input = payload + struct.pack(">d", session.ni) + bytes.fromhex(target_pid)

        packet = PMAPPacket.build(
            PMAPMessageType.D2D_M1_2,
            self.pid,
            payload,
            mac_input
        )

        print(f"[UAV-{self.id}] Send D2D M1/M2")

        self.SendData(packet)



    # =========================================================
    # Receive
    # =========================================================

    def ProcessReceivedData(self, packet_bytes):

        msg_type, pid, payload, mac = PMAPPacket.parse(packet_bytes)
        if pid != self.pid:
            print("[UAV-{self.id}] invalid PID!")

        # -----------------------------------------------------
        # Receive M2
        # -----------------------------------------------------

        if msg_type == PMAPMessageType.M2:

            plaintext = self.chaotic.decrypt_by_crp(
                payload,
                self.crp
            )

            pid, zsp, ni, ns = PMAPPlaintext.decode(
                PMAPPlaintext.M2,
                plaintext
            )
            if ni != self.ni:

                print(f"[UAV-{self.id}] Ni mismatch")
                return

            print(f"[UAV-{self.id}] ZSP verified")

            self.ns = ns

            self._send_M3_M4()


        # -----------------------------------------------------
        # Receive D2D M3
        # -----------------------------------------------------

        elif msg_type == PMAPMessageType.D2D_M3:

            plain = self.chaotic.decrypt_by_crp(payload, self.crp)

            pid_i, zsp, pid_j, ni, n1 = PMAPPlaintext.decode(
                PMAPPlaintext.D2D_M3,
                plain
            )

            print(f"[UAV-{self.id}] Receive D2D M3")
            session = self.D2D_sessions[pid_j]
            if ni != session.ni:
                print(f"[UAV-{self.id}] Ni mismatch")
                return

            print(f"[UAV-{self.id}] D2D: ZSP verified")

            session.n1 = n1

            session.ni = random.random()

            m4_plain = PMAPPlaintext.encode(
                PMAPPlaintext.D2D_M4,
                self.pid,
                self.zsp_id,
                pid_j,
                n1,
                session.ni
            )

            seed = self.chaotic.encrypt_by_crp(
                str(session.n1).encode() + str(session.ni).encode(),
                self.crp
            )

            challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)

            response = self.puf.generate_response(challenge)

            self.new_crp = [challenge, response]

            m5_plain = PMAPPlaintext.encode(
                PMAPPlaintext.D2D_M5,
                self.pid,
                self.zsp_id,
                pid_j,
                n1,
                session.ni,
                response
            )

            enc4 = self.chaotic.encrypt_by_crp(m4_plain, self.crp)
            enc5 = self.chaotic.encrypt_by_crp(m5_plain, self.crp)
            mac_input = enc4 + enc5 + struct.pack(">d", session.ni) +struct.pack(">d", response)
            packet = PMAPPacket.build(
                PMAPMessageType.D2D_M4_5,
                self.pid,
                enc4 + enc5,
                mac_input
            )

            self.SendData(packet)

            print(f"[UAV-{self.id}] Send D2D M4/M5")


        # -----------------------------------------------------
        # Receive D2D M6 M7 M8
        # -----------------------------------------------------

        elif msg_type == PMAPMessageType.D2D_M6_7_8:
            
            size6 = PMAPPlaintext.D2D_M6.size
            size7 = PMAPPlaintext.D2D_M7.size

            enc6 = payload[:size6]
            enc7 = payload[size6:size6 + size7]
            enc8 = payload[size6 + size7:]
            
            m6 = self.chaotic.decrypt_by_crp(enc6, self.crp)
            m7 = self.chaotic.decrypt_by_crp(enc7, self.crp)
            m8 = self.chaotic.decrypt_by_crp(enc8, self.crp)
            
            _, zsp, n2 = PMAPPlaintext.decode(PMAPPlaintext.D2D_M6, m6)
            
            _, _, _, ni = PMAPPlaintext.decode(
                PMAPPlaintext.D2D_M7,
                m7
            )
            _,_,_,_,pid_i = PMAPPlaintext.decode(
                PMAPPlaintext.D2D_M8,
                m8
            )
            print(f"n2 is {n2}")
            session = D2D_Session()
            session.n2 = n2
            session.ni = ni
            session.nj = random.random()
            self.D2D_sessions[pid_i] = session

            seed = self.chaotic.encrypt_by_crp(
                str(n2).encode() + str(session.nj).encode(),
                self.crp
            )

            challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)

            response = self.puf.generate_response(challenge)

            m9_plain = PMAPPlaintext.encode(
                PMAPPlaintext.D2D_M9,
                self.pid,
                self.zsp_id,
                pid_i,
                n2,
                session.nj
            )

            m10_plain = PMAPPlaintext.encode(
                PMAPPlaintext.D2D_M10,
                self.pid,
                self.zsp_id,
                pid_i,
                n2,
                session.nj,
                response
            )

            enc9 = self.chaotic.encrypt_by_crp(m9_plain, self.crp)
            enc10 = self.chaotic.encrypt_by_crp(m10_plain, self.crp)
            mac_input = enc9 + enc10 + struct.pack(">d", session.nj) + struct.pack(">d", response)
            packet = PMAPPacket.build(
                PMAPMessageType.D2D_M9_10,
                self.pid,
                enc9 + enc10,
                mac_input
            )

            self.SendData(packet)
            self.crp = [challenge,response]
            self.pid = hash_256(str(self.id) + str(response))
            session.session_key = \
            int(hash_256(str(session.ni)), 16) ^ \
            int(hash_256(str(session.nj)), 16)

            print(f"[UAV-{self.id}] D2D session key {hex(session.session_key)}")        


        # -----------------------------------------------------
        # Receive D2D M11
        # -----------------------------------------------------
        elif msg_type == PMAPMessageType.D2D_M11:

            plaintext = self.chaotic.decrypt_by_crp(
                payload,
                self.crp
            )

            pid_j, zsp, pid_i, ni, nj = PMAPPlaintext.decode(
                PMAPPlaintext.D2D_M11,
                plaintext
            )

            session = self.D2D_sessions.get(pid_i)

            if session is None:
                return

            session.nj = nj

            session.session_key = \
                int(hash_256(str(ni)), 16) ^ \
                int(hash_256(str(nj)), 16)

            print(
                f"[UAV-{self.id}] D2D Session confirmed "
                f"{hex(session.session_key)}"
            )

            new_pid = hash_256(str(self.id)+str(self.new_crp[1]))
            self.pid = new_pid
            self.crp = self.new_crp


    # =========================================================
    # Send M3 M4
    # =========================================================

    def _send_M3_M4(self):

        self.ni = random.random()
        seed = self.chaotic.encrypt_by_crp(
            str(self.ni).encode() + str(self.ns).encode(),
            self.crp
        )
        challenge = int(hash_256(seed.hex())[:13], 16) / (16 ** 13)
        response = self.puf.generate_response(challenge)
        m3_plain = PMAPPlaintext.encode(
            PMAPPlaintext.M3,
            self.pid,
            self.zsp_id,
            self.ns,
            self.ni
        )

        m4_plain = PMAPPlaintext.encode(
            PMAPPlaintext.M4,
            self.pid,
            self.zsp_id,
            self.ns,
            self.ni,
            response
        )
        enc3 = self.chaotic.encrypt_by_crp(m3_plain, self.crp)
        enc4 = self.chaotic.encrypt_by_crp(m4_plain, self.crp)

        mac_input = enc3 + enc4 + struct.pack(">d", self.ni) + struct.pack(">d", response)
        packet = PMAPPacket.build(
            PMAPMessageType.M3_4,
            self.pid,
            enc3+enc4,
            mac_input
        )
        self.SendData(packet)

        self.crp = [challenge, response]
        print(f"[UAV-{self.id}] CRP Update {challenge} {response}")

        self.pid = hash_256(str(self.id) + str(response))

        self.session_key = \
            int(hash_256(str(self.ni)), 16) ^ \
            int(hash_256(str(self.ns)), 16)

        print(f"[UAV-{self.id}] D2Z session key {hex(self.session_key)}")