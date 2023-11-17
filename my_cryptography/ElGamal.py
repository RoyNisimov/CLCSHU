import random
import sys
import math
from my_cryptography.Global import PrimeNumberGenerator


class ElGamalKey:
    def __init__(self, g, p, a=None, e=None):
        self.g = g
        self.p = p
        self.a = a
        self.e = e

    @staticmethod
    def construct(g, p):
        a = random.randint(2, p - 2)
        e = pow(g, a, p)
        return ElGamalKey(g, p, a, e)

    def __repr__(self):
        return f"{self.g = }\n{self.p = }\n{self.a = }\n{self.e = }\n"

class ElGamal:

    @staticmethod
    def generate_keys(n_bits=512):
        p = PrimeNumberGenerator.GeneratePrime(n_bits)
        g = random.randint(2, p - 2)
        a = random.randint(2, p - 2)
        e = pow(g, a, p)
        return ElGamalKey(g, p, e=e), ElGamalKey(g, p, a, e)

    @staticmethod
    def encrypt(key: ElGamalKey, message: bytes):
        msg_int = int.from_bytes(message, sys.byteorder)
        b = random.randint(2, key.p - 2)
        c1 = pow(key.g, b, key.p)
        c2 = (msg_int * pow(key.e, b, key.p)) % key.p

        return c1, c2

    @staticmethod
    def decrypt(key: ElGamalKey, c1: int, c2: int):
        assert key.a is not None
        x = pow(c1, key.a, key.p)
        m = (c2 * pow(x, key.p - 2, key.p)) % key.p
        m_bytes = m.to_bytes(m.bit_length(), sys.byteorder)
        return m_bytes.rstrip(b'\x00')

    @staticmethod
    def sign(key: ElGamalKey, message: bytes):
        m = int.from_bytes(message, sys.byteorder)
        k = random.randint(2, key.p - 2)
        while math.gcd(k, key.p - 1) != 1: k = random.randint(2, key.p - 2)
        s1 = pow(key.g, k, key.p)
        phi_n = key.p - 1
        inv = pow(k, -1, phi_n)
        s2 = (inv * (m - key.a * s1)) % phi_n
        if s2 == 0: ElGamal.sign(key, message)
        return m, s1, s2

    @staticmethod
    def verify(key: ElGamalKey, m, s1, s2):
        V = pow(key.e, s1, key.p) * pow(s1, s2, key.p)
        V = V % key.p
        W = pow(key.g, m, key.p)
        return V == W





if __name__ == '__main__':
    pub, priv = ElGamal.generate_keys(512)
    print(f'public key:\n{pub}')
    print(f'private key:\n{priv}')
    msg = b'test'
    c1, c2 = ElGamal.encrypt(pub, msg)
    print(c1)
    print(c2)
    m = ElGamal.decrypt(priv, c1, c2)
    print(m)
    m, s1, s2 = ElGamal.sign(priv, msg)
    ver = ElGamal.verify(pub, m, s1, s2)
    print(ver)
