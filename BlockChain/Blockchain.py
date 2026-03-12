from web3 import Web3
from solcx import compile_source, set_solc_version
import json
import os
import threading


class Web3BlockchainAdapter:
    """
    区块链适配器（线程安全版本）

    功能：
    - 连接本地区块链
    - 部署或加载合约
    - UAV 注册
    - PID 更新
    - 认证记录
    - 查询 PID 更新事件

    设计原则：
    - Adapter 无状态
    - Event cursor 由 ZSP 维护
    """

    def __init__(self,
                 enable: bool = True,
                 mode: str = "deploy",
                 rpc_url: str = "http://127.0.0.1:8545",
                 sol_path: str = "/home/zhang/UAV/BlockChain/UAVRegistry.sol",
                 solc_version: str = "0.8.0",
                 metadata_file: str = "uav_registry_deployed.json"):

        self.enable = enable
        self.mode = mode
        self.lock = threading.Lock()

        if not enable or mode == "none":
            self.enabled = False
            return

        self.rpc_url = rpc_url
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))

        if not self.w3.is_connected():
            raise RuntimeError("Blockchain RPC not reachable")

        self.account = self.w3.eth.accounts[0]

        if mode == "deploy":
            self._deploy_contract(sol_path, solc_version, metadata_file)

        elif mode == "load":
            self._load_contract(metadata_file)

        else:
            raise ValueError(f"Unknown blockchain mode: {mode}")

        self.enabled = True

    def __del__(self):
        print("[Blockchain] Adapter destroyed")

    # ==================================================
    # 合约部署
    # ==================================================

    def _deploy_contract(self, sol_path, solc_version, metadata_file):

        set_solc_version(solc_version)

        with open(sol_path) as f:
            source = f.read()

        compiled = compile_source(source, output_values=["abi", "bin"])

        _, interface = compiled.popitem()

        self.abi = interface["abi"]
        bytecode = interface["bin"]

        Contract = self.w3.eth.contract(
            abi=self.abi,
            bytecode=bytecode
        )

        with self.lock:

            tx = Contract.constructor().transact({
                "from": self.account
            })

            receipt = self.w3.eth.wait_for_transaction_receipt(tx)

        self.contract_address = receipt.contractAddress

        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.abi
        )

        with open(metadata_file, "w") as f:

            json.dump({
                "rpc": self.rpc_url,
                "contract_address": self.contract_address,
                "abi": self.abi,
                "account": self.account,
            }, f, indent=2)

        print("[Blockchain] Contract deployed and ready")

    # ==================================================
    # 加载合约
    # ==================================================

    def _load_contract(self, metadata_file):

        if not os.path.exists(metadata_file):
            raise RuntimeError("Blockchain metadata file not found")

        with open(metadata_file) as f:
            meta = json.load(f)

        self.contract_address = meta["contract_address"]
        self.abi = meta["abi"]
        self.account = meta["account"]

        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.abi
        )

        print("[Blockchain] Contract loaded")

    # ==================================================
    # 工具函数
    # ==================================================

    def _pid_to_bytes32(self, pid: str):

        if pid.startswith("0x"):
            pid = pid[2:]

        return bytes.fromhex(pid)

    def _bytes32_to_pid(self, value):
        """
        将链上 bytes32 转换为 PID hex string
        兼容:
        - HexBytes
        - bytes
        - str
        """

        if isinstance(value, str):

            if value.startswith("0x"):
                return value[2:]

            return value

        if hasattr(value, "hex"):
            return value.hex()

        if isinstance(value, bytes):
            return value.hex()

        return str(value)

    # ==================================================
    # UAV 注册
    # ==================================================

    def register_uav(self, pid: str):

        if not self.enabled:
            return

        try:

            pid_b = self._pid_to_bytes32(pid)

            with self.lock:

                self.contract.functions.registerUAV(
                    pid_b
                ).transact({
                    "from": self.account
                })

            print(f"[Blockchain] UAV registered {pid[:8]}")

        except Exception as e:

            print("[Blockchain] register_uav failed:", e)

    # ==================================================
    # UAV 是否有效
    # ==================================================

    def is_valid_uav(self, pid: str) -> bool:

        if not self.enabled:
            return False

        try:

            with self.lock:

                return self.contract.functions.isValidUAV(
                    self._pid_to_bytes32(pid)
                ).call()

        except Exception as e:

            print("[Blockchain] is_valid_uav failed:", e)

            return False

    # ==================================================
    # 记录认证结果
    # ==================================================

    def record_auth_event(self, pid: str, result: bool):

        if not self.enabled:
            return

        try:

            with self.lock:

                self.contract.functions.recordAuth(
                    self._pid_to_bytes32(pid),
                    result
                ).transact({
                    "from": self.account
                })

        except Exception as e:

            print("[Blockchain] record_auth_event failed:", e)

    # ==================================================
    # PID 更新
    # ==================================================

    def update_pid(self, old_pid: str, new_pid: str):

        if not self.enabled:
            return

        try:

            print(
                f"[Blockchain] PID update "
                f"{old_pid[:6]} -> {new_pid[:6]}"
            )

            old_b = self._pid_to_bytes32(old_pid)
            new_b = self._pid_to_bytes32(new_pid)

            with self.lock:

                self.contract.functions.updatePID(
                    old_b,
                    new_b
                ).transact({
                    "from": self.account
                })

        except Exception as e:

            print("[Blockchain] update_pid failed:", e)

    # ==================================================
    # 查询 PID 更新事件（无状态）
    # ==================================================

    def get_pid_update_events(self, from_block: int, to_block: int):

        if not self.enabled:
            return []

        try:

            with self.lock:

                events = self.contract.events.PIDUpdated.get_logs(
                    from_block=from_block,
                    to_block=to_block
                )

            result = []

            for e in events:

                result.append({
                    "old_pid": self._bytes32_to_pid(
                        e["args"]["oldPID"]
                    ),
                    "new_pid": self._bytes32_to_pid(
                        e["args"]["newPID"]
                    )
                })

            return result

        except Exception as e:

            print("[Blockchain] event poll failed:", e)

            return []