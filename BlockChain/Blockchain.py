from web3 import Web3
from solcx import compile_source, set_solc_version
import hashlib
import json
import os


class Web3BlockchainAdapter:
    """
    区块链适配器（自包含）
    - 连接区块链
    - 可选：编译 + 部署合约
    - 提供 ZSP 所需的区块链接口
    """

    def __init__(self,
                 enable: bool = True,
                 mode: str = "deploy",
                 rpc_url: str = "http://127.0.0.1:8545",
                 sol_path: str = "/home/zhang/UAV/BlockChain/UAVRegistry.sol",
                 solc_version: str = "0.8.0",
                 metadata_file: str = "uav_registry_deployed.json"):
        """
        :param enable: 是否启用区块链
        :param mode:
            - "deploy": 启动时编译并部署合约（仅测试）
            - "load"  : 从文件加载已部署合约（推荐）
            - "none"  : 不使用区块链（退化为空实现）
        """

        self.enable = enable
        self.mode = mode

        if not self.enable or mode == "none":
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

    # ==================================================
    # 内部：部署模式
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

        tx = Contract.constructor().transact({"from": self.account})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx)

        self.contract_address = receipt.contractAddress
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.abi
        )

        # 持久化（非常关键）
        with open(metadata_file, "w") as f:
            json.dump({
                "rpc": self.rpc_url,
                "contract_address": self.contract_address,
                "abi": self.abi,
                "account": self.account,
            }, f, indent=2)

        self.enabled = True
        print("[Blockchain] Contract deployed and ready")

    # ==================================================
    # 内部：加载模式
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

        self.enabled = True
        print("[Blockchain] Contract loaded")

    # ==================================================
    # ZSP / PMAP 使用的接口
    # ==================================================

    def _pid_to_bytes32(self, pid: str):
        return hashlib.sha256(pid.encode()).digest()

    def is_valid_uav(self, pid: str) -> bool:
        if not self.enabled:
            return False
        return self.contract.functions.isValidUAV(
            self._pid_to_bytes32(pid)
        ).call()

    def record_auth_event(self, pid: str, result: bool):
        if not self.enabled:
            return
        self.contract.functions.recordAuth(
            self._pid_to_bytes32(pid),
            result
        ).transact({"from": self.account})
    
    def register_uav(self, pid: str):
        """
        将 UAV 的 PID 注册到区块链（仅存状态）
        """
        if not self.enabled:
            return

        pid_b = self._pid_to_bytes32(pid)
        self.contract.functions.registerUAV(
            pid_b
        ).transact({"from": self.account})

