from abc import ABC, abstractmethod

class BaseKeyGenerator(ABC):

    def __init__(self,key_size:int = 256):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    @abstractmethod
    def generate_key_pair(self):
        pass

    @abstractmethod
    def get_public_params(self):
        pass