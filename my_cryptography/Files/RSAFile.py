from .EncryptedFile import EncryptedFile
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class RSAFile(EncryptedFile, prefix='rsa'):
    def __init__(self, path, key):
        if isinstance(self.key, str):
            self.key = self.key.encode()
        key1 = input("Passphrase: ").encode()
        self.rsa_key = RSA.import_key(self.key, passphrase=key1)


    def read(self):
        with open(self.file, 'rb') as f: data = f.read()
        cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
        dec = cipher_rsa.decrypt(data)
        return dec

    def write(self, data: bytes):
        cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
        enc = cipher_rsa.encrypt(data)
        with open(self.file, 'wb') as f: f.write(enc)

    def sign(self, data: bytes):
        message = data
        h = SHA256.new(message)
        signature = pkcs1_15.new(self.rsa_key).sign(h)
        with open(self.file, 'wb') as f: f.write(signature)

    def verify(self, data: bytes):
        h = SHA256.new(data)
        with open(self.file, 'rb') as f: signature = f.read()
        try:
            pkcs1_15.new(self.rsa_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

