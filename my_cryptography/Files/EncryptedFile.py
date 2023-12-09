from ..Global import Common
# https://github.com/mCodingLLC/VideosSampleCode/blob/master/videos/076_new_vs_init_in_python/new_vs_init.py
from CHA.Piranha import Piranha
from ..Exeptions import UnauthorisedChange
from CHA import BlackFrog, BlackFrogKey, OAEP
from Crypto.Cipher import AES, ChaCha20, DES, Blowfish
from Crypto.Util.Padding import pad, unpad



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

    def write(self, data: bytes, file_out=None):
        raise NotImplementedError

    def sign(self, data: bytes, file_out=None):
        raise NotImplementedError

    def verify(self, data: bytes) -> bool:
        raise NotImplementedError


class Plaintext(EncryptedFile, prefix='file'):
    def read(self):
        with open(self.file, 'rb') as f:
            return f.read()

    def write(self, data: bytes, file_out=None):
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

    def write(self, data: bytes, file_out=None):
        if file_out is None: file_out = self.file
        cipher = self.xor_bytes_with_key(data)
        with open(file_out, 'wb') as f:
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

    def write(self, data: bytes, file_out=None):
        if file_out is None: file_out = self.file
        cipher = Piranha(self.key, Piranha.CTR)
        encrypted = cipher.encrypt(data=data)
        hmac = cipher.HMAC()
        with open(file_out, 'wb') as f:
            f.write(hmac + cipher.iv + encrypted)
class BlackFrogFile(EncryptedFile, prefix='black_frog'):
    def __init__(self, path, key):
        if isinstance(self.key, str):
            self.key = self.key.encode()
        if b"----BEGIN BLACKFROG PRIVATE KEY----" in self.key:
            key1 = input("Passphrase: ").encode()
            self.black_frog_key = BlackFrogKey.load(self.key, key1)
        else:
            self.black_frog_key = BlackFrogKey.load(self.key)


    def read(self):
        with open(self.file, 'rb') as f: data = f.read()
        dec = OAEP.decrypt_BlackFrog(self.black_frog_key, data).rstrip(b"\x00")
        return dec

    def write(self, data: bytes, file_out=None):
        if file_out is None: file_out = self.file
        enc = OAEP.encrypt_BlackFrog(self.black_frog_key, data)
        with open(file_out, 'wb') as f: f.write(enc)

class AES128File(EncryptedFile, prefix='aes128'):
    def __init__(self, path, key):
        if isinstance(self.key, str):
            self.key = self.key.encode()



    def read(self):
        with open(self.file, 'rb') as f:
            tag = f.read(16)
            nonce = f.read(16)
            ciphertext = f.read()
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
        except ValueError:
            raise UnauthorisedChange("Key incorrect or message corrupted")
        return plaintext


    def write(self, data: bytes, file_out=None):
        if file_out is None: file_out = self.file
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)
        d = tag + nonce + ciphertext
        with open(file_out, 'wb') as f:
            f.write(d)

