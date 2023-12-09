from .EncryptedFile import EncryptedFile
from ..ElGamal import ElGamalKey, ElGamal
from ..OAEP import OAEP
import json
from ..Exeptions import UnauthorisedChange
class ElGamalFile(EncryptedFile, prefix='elgamal'):
    def __init__(self, path, key):
        if isinstance(self.key, str):
            self.key = self.key.encode()
        if b"----BEGIN ElGamal PRIVATE KEY----" in self.key:
            key1 = input("Passphrase: ").encode()
            self.elGamalKey = ElGamalKey.import_key(self.key, key1)
        else:
            self.elGamalKey = ElGamalKey.import_key(self.key)



    def read(self):
        with open(self.file, "r") as f:
            data = json.loads(f.read())
        c1, c2 = data['c1'], data["c2"]
        pt = OAEP.decrypt_ElGamal(self.elGamalKey, c1, c2).rstrip(b"\x00")
        return pt



    def write(self, data: bytes, file_out=None):
        if file_out is None: file_out = self.file
        c1, c2 = OAEP.encrypt_ElGamal(self.elGamalKey, data)
        s = json.dumps({"c1": c1, "c2": c2}, indent=2)
        with open(file_out, "w") as f:
            f.write(s)

    def sign(self, data: bytes, file_out=None):
        if file_out is None: file_out = self.file
        m, s1, s2 = ElGamal.sign(key=self.elGamalKey, message=data)
        s = json.dumps({"m": m, "s1": s1, "s2": s2}, indent=2)
        with open(file_out, "w") as f:
            f.write(s)

    def verify(self, data: bytes) -> bool:
        with open(self.file, "r") as f:
            data1 = json.loads(f.read())
        m, s1, s2 = data1["m"], data1['s1'], data1["s2"]
        v = ElGamal.verify(self.elGamalKey, m, s1, s2)
        if not v: raise UnauthorisedChange("The message isn't from the key owner!")
        return v