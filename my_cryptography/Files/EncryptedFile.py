from ..Global import Common
# https://github.com/mCodingLLC/VideosSampleCode/blob/master/videos/076_new_vs_init_in_python/new_vs_init.py
from CHA.Piranha import Piranha
from CHA.KRY import KRY
from ..Exeptions import UnauthorisedChange
from CHA import BlackFrog, BlackFrogKey, OAEP
from Crypto.Cipher import AES, ChaCha20, DES, Blowfish
from Crypto.Util.Padding import pad, unpad
import json
from base64 import b64encode, b64decode


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

    def read_write(self, file_out: str = None) -> None:
        data = self.read()
        self.write(data, file_out)


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
            data = f.read()
        cipher = Piranha(self.key, Piranha.EAA)
        d = Piranha.unpad(cipher.decrypt(data))
        return d

    def write(self, data: bytes, file_out=None):
        if file_out is None: file_out = self.file
        cipher = Piranha(self.key, Piranha.EAA)
        encrypted = cipher.encrypt(data=data)
        with open(file_out, 'wb') as f:
            f.write(encrypted)

class KRYFile(EncryptedFile, prefix='kry'):
    def __init__(self, path, key):
        if isinstance(self.key, str):
            self.key = self.key.encode()


    def read(self):
        with open(self.file, 'rb') as f:
            data = f.read()
        cipher = KRY(self.key, KRY.EAA)
        d = Piranha.unpad(cipher.decrypt(data))
        return d

    def write(self, data: bytes, file_out=None):
        if file_out is None: file_out = self.file
        cipher = KRY(self.key, KRY.EAA)
        data = KRY.pad(data)
        encrypted = cipher.encrypt(data=data)
        with open(file_out, 'wb') as f:
            f.write(encrypted)


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
        return unpad(plaintext, AES.block_size)


    def write(self, data: bytes, file_out=None):
        if file_out is None: file_out = self.file
        data = pad(data, AES.block_size)
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)
        d = tag + nonce + ciphertext
        with open(file_out, 'wb') as f:
            f.write(d)

class ChaCha20File(EncryptedFile, prefix='chacha20'):
    def __init__(self, path, key):
        if isinstance(self.key, str):
            self.key = self.key.encode()
        assert len(self.key) == 32



    def read(self):
        with open(self.file, 'r') as f:
            json_input = f.read()
        try:
            b64 = json.loads(json_input)
            nonce = b64decode(b64['nonce'])
            ciphertext = b64decode(b64['ciphertext'])
            cipher = ChaCha20.new(key=self.key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext
        except (ValueError, KeyError):
            print("Incorrect decryption")


    def write(self, data: bytes, file_out=None):
        if file_out is None: file_out = self.file
        cipher = ChaCha20.new(key=self.key)
        ciphertext = cipher.encrypt(data)
        nonce = b64encode(cipher.nonce).decode('utf-8')
        ct = b64encode(ciphertext).decode('utf-8')
        result = json.dumps({'nonce': nonce, 'ciphertext': ct})
        with open(file_out, 'w') as f:
            f.write(result)


