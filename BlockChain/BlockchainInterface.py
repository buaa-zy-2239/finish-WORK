from abc import ABC, abstractmethod


class BlockchainInterface(ABC):

    @abstractmethod
    def is_valid_uav(self, pid: str) -> bool:
        pass

    @abstractmethod
    def record_auth_event(self, pid: str, result: bool):
        pass
