from ..Global import Common
# https://github.com/mCodingLLC/VideosSampleCode/blob/master/videos/076_new_vs_init_in_python/new_vs_init.py
from CHA.Piranha import Piranha
from ..Exeptions import UnauthorisedChange

class EncryptedFile:  # DO NOT USE ANY OF THESE FOR REAL ENCRYPTION
    _registry = {}

    def __init_subclass__(cls, prefix, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._registry[prefix] = cls

    def __new__(cls, path: str, key=None):
        prefix, sep, suffix = path.partition(':///')
        if sep:
            file = suffix
        else:
            file = prefix
            prefix = "file"
        subclass = cls._registry[prefix]
        obj = object.__new__(subclass)
        obj.file = file
        obj.key = key
        return obj

    def read(self) -> bytes:
        raise NotImplementedError

    def write(self, data: bytes):
        raise NotImplementedError

    def sign(self, data: bytes):
        raise NotImplementedError

    def verify(self, data: bytes) -> bool:
        raise NotImplementedError


class Plaintext(EncryptedFile, prefix='file'):
    def read(self):
        with open(self.file, 'rb') as f:
            return f.read()

    def write(self, data: bytes):
        with open(self.file, 'wb') as f:
            f.write(data)




class XOR(EncryptedFile, prefix='xor'):
    def __init__(self, path, key):
        if isinstance(self.key, str):
            self.key = self.key.encode()


    def xor_bytes_with_key(self, b: bytes) -> bytes:
        return Common.repeated_key_xor(b, self.key)

    def read(self):
        with open(self.file, 'rb') as f:
            btext = f.read()
        text = self.xor_bytes_with_key(btext)
        return text

    def write(self, data: bytes):
        cipher = self.xor_bytes_with_key(data)
        with open(self.file, 'wb') as f:
            f.write(cipher)

class PiranhaFile(EncryptedFile, prefix='piranha'):
    def __init__(self, path, key):
        if isinstance(self.key, str):
            self.key = self.key.encode()


    def read(self):
        with open(self.file, 'rb') as f:
            hmac = f.read(64)
            iv = f.read(16)
            data = f.read()
        cipher = Piranha(self.key, Piranha.CTR, iv=iv)
        d = Piranha.unpad(cipher.decrypt(data))
        v = cipher.verify(data=None, mac=hmac)
        if not v: raise UnauthorisedChange(f"Message '{d}' doesn't fit the given HMAC!")
        return d

    def write(self, data: bytes):
        cipher = Piranha(self.key, Piranha.CTR)
        encrypted = cipher.encrypt(data=data)
        hmac = cipher.HMAC()
        with open(self.file, 'wb') as f:
            f.write(hmac + cipher.iv + encrypted)
