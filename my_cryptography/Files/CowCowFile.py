from .EncryptedFile import EncryptedFile
from CHA import CowCowModes

class ElGamalFile(EncryptedFile, prefix='cowcow'):
    def __init__(self, path, key):
        if isinstance(self.key, str):
            self.key = self.key.encode()
        assert len(self.key) == 32


    def read(self):
        cipher = CowCowModes(self.key, CowCowModes.EAA)
        with open(self.file, "rb") as f:
            data = cipher.decrypt(f.read())
        return CowCowModes.unpad(data)



    def write(self, data: bytes, file_out=None):
        if file_out is None: file_out = self.file
        cipher = CowCowModes(self.key, CowCowModes.EAA)
        data = CowCowModes.pad(data)
        with open(file_out, "wb") as f:
            f.write(cipher.encrypt(data))
