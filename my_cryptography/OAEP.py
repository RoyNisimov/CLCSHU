import hashlib
import secrets
import sys
from my_cryptography import ElGamal
from CHA import BlackFrog, BlackFrogKey


class OAEP:
    @staticmethod
    def repeated_key_xor(plain_text, key):
        pt = plain_text
        len_key = len(key)
        encoded = []

        for i in range(0, len(pt)):
            encoded.append(pt[i] ^ key[i % len_key])
        return bytes(encoded)

    @staticmethod
    def oaep_pad(message):
        nonce = secrets.randbits(32)
        nonce = nonce.to_bytes(32, sys.byteorder)
        mm = message + b"\x00" * (32-len(message))
        G = OAEP.repeated_key_xor(mm, hashlib.sha256(nonce).digest())
        H = OAEP.repeated_key_xor(nonce, hashlib.sha256(G).digest())
        return G + H

    @staticmethod
    def oaep_unpad(message):
        oaep_step2 = message + b'\x00' * (64 - len(message))
        G = oaep_step2[:32]
        H = oaep_step2[32:64]
        nonce = OAEP.repeated_key_xor(H, hashlib.sha256(G).digest())[:32]
        mm = OAEP.repeated_key_xor(G, hashlib.sha256(nonce).digest())
        return mm

    @staticmethod
    def encrypt(msg, n, pub):
        oaep = OAEP.oaep_pad(msg)
        m_int = int.from_bytes(oaep, sys.byteorder)
        ret_int = pow(m_int, pub, n)
        ret_b = ret_int.to_bytes(ret_int.bit_length(), sys.byteorder)
        return ret_b

    @staticmethod
    def decrypt(ciphertext, n, priv):
        rsa_int = int.from_bytes(ciphertext, sys.byteorder)
        oaep_step1 = pow(rsa_int, priv, n)
        return OAEP.oaep_unpad(oaep_step1)

    @staticmethod
    def encrypt_ElGamal(key: ElGamal.ElGamalKey, msg):
        oaep = OAEP.oaep_pad(msg)
        oaep_int = int.from_bytes(oaep, sys.byteorder)
        if oaep_int >= key.p: OAEP.encrypt_ElGamal(key, msg)
        c1, c2 = ElGamal.ElGamal.encrypt(key, oaep)
        return c1, c2

    @staticmethod
    def decrypt_ElGamal(key, c1, c2):
        oaep = ElGamal.ElGamal.decrypt(key, c1, c2)
        return OAEP.oaep_unpad(oaep)

    @staticmethod
    def encrypt_BlackFrog(key: BlackFrogKey, msg: bytes):
        oaep = OAEP.oaep_pad(msg)
        oaep_int = int.from_bytes(oaep, sys.byteorder)
        if oaep_int >= key.n: OAEP.encrypt_BlackFrog(key, msg)
        cipher = BlackFrog.encrypt(key, oaep)
        return cipher

    @staticmethod
    def decrypt_BlackFrog(key: BlackFrogKey, cipher: bytes):
        oaep = BlackFrog.decrypt(key, cipher)
        return OAEP.oaep_unpad(oaep)

if __name__ == '__main__':
    pub, priv = ElGamal.ElGamal.generate_keys(1024)
    print(pub)
    print(priv)

    msg = b'test'

    c1, c2 = OAEP.encrypt_ElGamal(pub, msg)
    print(c1, c2)
    m = OAEP.decrypt_ElGamal(priv, c1, c2).rstrip(b'\x00')
    print(m)
