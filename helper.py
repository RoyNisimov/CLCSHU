import sys

import CHA
from CHA import BlackFrog, BlackFrogKey, OAEP
import string
import hashlib
import ast
import math
from cryptography.fernet import Fernet
from CLCSHU.Steganography.PNGs import LSB
from CLCSHU.Steganography.PNGs import EOF
from CLCSHU.my_cryptography import ElGamal, OAEP, Skipjack
from CLCSHU.my_cryptography.Global import Common
import json
# pycryptodome:
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA, DSA
from base64 import b64encode, b64decode
from Crypto.Hash import BLAKE2b, BLAKE2s, SHA256, HMAC
from Crypto.Signature import DSS


class Call:
    def visit(self, branch_name: str, method_name: str):
        """
        :type method_name: str
        :type branch_name: str
        """
        to_call = getattr(self, 'visit_' + branch_name + "_" + method_name, None)
        if to_call is None: raise Exception(f"No method named {method_name} found in the {branch_name} branch_name!")
        to_call()

    #   --------------Cryptography start--------------

    @staticmethod
    def visit_cryptography_repeated_key_xor():
        modes = ['Info', 'Use']
        for index, name in enumerate(modes):
            print("{0}: {1}".format(index, name))
        index = int(input("Enter choice number: "))
        to_call = modes[index % len(modes)]
        if to_call == 'Use':

            plain = input("Message:\n")
            key = input("Key:\n").encode()
            input_type = input("Input plaintext in hex or utf-8? H/U ").lower()
            if input_type == 'u': plain = plain.encode()
            elif input_type == 'h': plain = bytes.fromhex(plain)
            xor = Common.repeated_key_xor(plain, key)
            type1 = input("hex or bytes? H/B\n").lower()
            if type1 == 'h':
                print(xor.hex())
                return xor.hex()
            elif type1 == 'b':
                print(xor)
                return xor
        if to_call == 'Info':
            print("""
                                XOR
------------------------------------------------------------------------
XOR is a logic gate that is use heavily in cryptography

------------------
  A  |  B  | OUT |
------------------
  0  |  1  |  1  |
  0  |  0  |  0  |
  1  |  1  |  0  |
  1  |  0  |  1  |
------------------

You might have tried to use the '^' operator in python before, confusing this for the power operator. '^' is the XOR operator.

'https://dev.to/wrongbyte/cryptography-basics-breaking-repeated-key-xor-ciphertext-1fm2'

            """)

    @staticmethod
    def visit_cryptography_Skipjack():
        print("Skipjack: 'https://www.youtube.com/watch?v=cMm5cd-WB2s'")
        print("Source code: 'https://github.com/jacksoninfosec/skipjack/blob/main/skipjack.py'")
        key = input("Key (like: '0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11'): \n")
        key = ast.literal_eval(f"[{key}]")
        both_or_encrypt_or_decrypt = input("Encrypt, decrypt, or both. E/D/B:\n").lower()
        sj = Skipjack.SkipJack()
        if both_or_encrypt_or_decrypt == 'e':
            PT = input('message: ').encode()
            PT = int.from_bytes(PT, sys.byteorder)
            cipher = sj.encrypt(PT, key)
            print(cipher)
            return cipher
        elif both_or_encrypt_or_decrypt == 'd':
            cipher = int(input('cipher: ').encode().hex(), 16)
            pt = sj.decrypt(cipher, key)
            pt = pt.to_bytes(pt.bit_length(), sys.byteorder).rstrip(b'\x00').decode()
            print(pt)
            return pt
        elif both_or_encrypt_or_decrypt == 'b':
            PT = input('message: ').encode()
            PT = int.from_bytes(PT, sys.byteorder)
            cipher = sj.encrypt(PT, key)
            print(f"Cipher = {cipher}")
            pt = sj.decrypt(cipher, key)
            pt = pt.to_bytes(pt.bit_length(), sys.byteorder).rstrip(b'\x00').decode()
            print(pt)
            return cipher

    @staticmethod
    def visit_cryptography_Feistel64XOR():
        print("WARNING: this is my own Feistel network implementation, I don't know if I did something insecure there. source code: 'https://github.com/RoyNisimov1/CHA/blob/main/CHA/CHAF.py'")
        print("more info on Feistel ciphers: 'https://www.youtube.com/watch?v=FGhj3CGxl8I'")
        key = input('key').encode()



        def fXOR(b):
            return Common.repeated_key_xor(b, key)

        s = input("Message:\n")
        both_or_encrypt_or_decrypt = input("Encrypt, decrypt, or both. E/D/B:\n").lower()
        if both_or_encrypt_or_decrypt == 'e':
            obj = CHA.FeistelN().DE(s.encode(), 8, fXOR, 'e', 's')
            print(obj)
            return obj
        elif both_or_encrypt_or_decrypt == 'd':
            obj = CHA.FeistelN().DE(s, 8, fXOR, 'd', 's')
            print(obj.decode().strip())
            return obj
        elif both_or_encrypt_or_decrypt == 'b':
            e = CHA.FeistelN().DE(s.encode(), 8, fXOR, 'e', 's')
            print(e)
            d = CHA.FeistelN().DE(e, 8, fXOR, 'd', 's')
            print(d.decode().strip())
            return e, d.decode().strip()

    @staticmethod
    def visit_cryptography_Fernet():
        key = input('Fernet key:\n').encode()
        if len(key) == 0:
            key = Fernet.generate_key()
        print(f"Your key is: {key}")
        f = Fernet(key)
        encrypt_or_decrypt = input("encrypt or decrypt E/D: ").lower()
        if encrypt_or_decrypt == 'e':
            msg = input("Message:\n").encode()
            output = f.encrypt(msg)
            print(output)
            return output
        elif encrypt_or_decrypt == 'd':
            ciphertxt = input("Ciphertext:\n").encode()
            output = f.decrypt(ciphertxt)
            print(output)
            return output

    @staticmethod
    def visit_cryptography_ByteToIntXOR():
        modes = ['Info', 'Use']
        for index, name in enumerate(modes):
            print("{0}: {1}".format(index, name))
        index = int(input("Enter choice number: "))
        to_call = modes[index % len(modes)]
        if to_call == 'Use':

            plain = input("Message:\n")
            key = input("Key:\n").encode()
            input_type = input("Input plaintext in hex or utf-8? H/U ").lower()
            if input_type == 'u':
                plain = plain.encode()
            elif input_type == 'h':
                plain = bytes.fromhex(plain)
            xor = Common.xor(plain, key)
            type1 = input("hex or bytes? H/B\n").lower()
            if type1 == 'h':
                print(xor.hex())
                return xor.hex()
            elif type1 == 'b':
                print(xor)
                return xor
        if to_call == 'Info':
            print("""
                                        XOR
        ------------------------------------------------------------------------
        XOR is a logic gate that is use heavily in cryptography

        ------------------
          A  |  B  | OUT |
        ------------------
          0  |  1  |  1  |
          0  |  0  |  0  |
          1  |  1  |  0  |
          1  |  0  |  1  |
        ------------------

        You might have tried to use the '^' operator in python before, confusing this for the power operator. '^' is the XOR operator.

        'https://dev.to/wrongbyte/cryptography-basics-breaking-repeated-key-xor-ciphertext-1fm2'

                    """)

    @staticmethod
    def visit_cryptography_ElGamal():
        print("WARNING: This is my implementation of ElGamal and OAEP, probably not the safest! Also note that RSA is considered a better asymmetric funtion that can encrypt/decrypt, sign, and key exchange. While ElGamal can only encrypt/decrypt and key exchange")
        print("I couldn't made signing possible for some reason")
        modes = ['Use', 'Info']
        for index, name in enumerate(modes):
            print("{0}: {1}".format(index, name))
        index = int(input("Enter choice number: "))
        to_call = modes[index % len(modes)]
        if to_call == 'Use':
            file = input("save file name?\n")
            user_input = input("Generate, encrypt, decrypt? G/E/D: ").lower()
            if user_input == "g":
                size = input("size? default is 512 (not secure enough)")
                if len(size) == 0: size = 512
                else:
                    size = int(size)
                pub, priv = ElGamal.ElGamal.generate_keys(size)
                print(f'{pub = }\n{priv = }')
                data = {"pub": {
                        "p": pub.p,
                        "g": pub.g,
                        "e": pub.e},
                    "priv": {
                        "p": priv.p,
                        "g": priv.g,
                        "a": priv.a,
                        "e": priv.e}}
                with open(file, 'w') as f:
                    f.write(json.dumps(data))
                return data
            elif user_input == "e":
                with open(file, 'r') as f:
                    data = json.loads(f.read())
                m = input('message:\n').encode('utf-8')
                key = ElGamal.ElGamalKey(data['pub']['g'], data['pub']['p'], e=data['pub']['e'])
                c1, c2 = OAEP.OAEP.encrypt_ElGamal(key, m)
                print(c1)
                print(c2)
                file_out = input('file out: ')
                edata = {"c1": c1, "c2": c2}
                with open(file_out, 'w') as f:
                    f.write(json.dumps(edata))
                return c1, c2
            elif user_input == "d":
                with open(file, 'r') as f:
                    data = json.loads(f.read())
                file_in = input('file in:\n')
                with open(file_in, 'r') as f:
                    edata = json.loads(f.read())
                key = ElGamal.ElGamalKey(data['priv']['g'], data['priv']['p'], a=data['priv']['a'], e=data['priv']['e'])
                m = OAEP.OAEP.decrypt_ElGamal(key, edata["c1"], edata["c2"])
                print(m.rstrip(b'\x00'))
                return m
        elif to_call == 'Info':
            print("""The ElGamal cryptosystem was invented in 1985, by Taher Elgamal.
                Key Generation
----------------------------------------------
Let P be a prime number
Let G = 1 < G < P-1 (G must be a primitive root if you want signing)
Let X = 1 < X < P-1 (Private key)
Then calculate Y:
Y = G**X mod P
Public: {P,G,Y}
Private: {X}

                Encryption
----------------------------------------------
M: your message (as a number, M < P -1)
Let B = 1 < B < P - 1
Then calculate:
C1 = G**B mod P
C2 = (M * Y**B) mod P
Then the cipher text is: {C1, C2}

                Decryption
----------------------------------------------
XM = C1**X mod P
M = (C2 * XM**(P-2)) mod P
                  Example
----------------------------------------------
P = 23
G = 7
X = 15
Y = 7**15 mod 23 = 14

Public: {P = 23, G = 7, Y = 14}
Private: {X = 15}

M = 4
B = 10
C1 = 7**10 mod 23 = 13
C2 = 4 * 14**10 mod 23 = 3

XM = 13 ** 15 mod 23 = 18
M = 3 * 18**21 mod 23 = 4
----------------------------------------------

Please note that this variation of ElGamal uses OAEP (commonly used with RSA)
""")



    @staticmethod
    def visit_cryptography_RSA():
        print("This uses pycryptodome rsa with PKCS1_OAEP")
        print("Pycryptodome: 'https://pypi.org/project/pycryptodome/'")
        print("Source for RSA: 'https://www.youtube.com/watch?v=D_PfV_IcUdA'")
        modes = ['Info', 'Use']
        for index, name in enumerate(modes):
            print("{0}: {1}".format(index, name))
        index = int(input("Enter choice number: "))
        to_call = modes[index % len(modes)]
        if to_call == 'Info':
            print("""
RSA stands for Rivest–Shamir–Adleman. 
It was invented in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman

            How RSA works and how the keys are calculated?
------------------------------------------------------------------------
let p and q = Two large primes
n = p * q
phi_n = (p-1)*(q-1)
e = gcd(e, phi_n) = 1, i.e: phi_n / e != integer
e*d mod phi_n = 1
You can only share the e and n!

                            Encryption
------------------------------------------------------------------------
Encryption works like this:

ciphertext = message**e % n
message = ciphertext**d % n
for example:
e = 3
d = 3
n = 15
(p, q = 3, 5)
so lets say we want to encrypt '2'
we do:
ciphertext = 2**3 % 15 = 8 (the 3 is e)
message = 8**3 % 15 = 2 (the 3 is d)
                              Verifying
------------------------------------------------------------------------
RSA is an important algorithm that can verify authenticity too. because the keys are linked we do can do:
sign = m**d % n # d is the privet key
verify = c**e % n # e is the public key

d should be private, that's the assumption at least
e can be public
------------------------------------------------------------------------
This implementation uses PyCryptodome rsa with PKCS1_OAEP.
Wiki about OAEP: 'https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding'
Wiki about PKCS1: 'https://en.wikipedia.org/wiki/PKCS_1'

""")
        elif to_call == 'Use':
            gen_or_encrypt_decrypt = input("Generate, encrypt or decrypt G/E/D: ").lower()
            passphrase = input('passphrase: ')
            file_name = input('private key file name (will append .pem): ')
            file_name += '.pem'
            file_name_pub = input('public key file name (will append .pem): ')
            file_name_pub += '.pem'
            if gen_or_encrypt_decrypt == 'g':
                key = RSA.generate(2048)
                with open(file_name, 'wb') as f:
                    f.write(key.exportKey('PEM', passphrase=passphrase))
                with open(file_name_pub, 'wb') as f:
                    f.write(key.publickey().export_key('PEM'))
                return
            elif gen_or_encrypt_decrypt == 'e':
                file_out = input("file out:\n")
                encoded_key = open(file_name_pub, "rb").read()
                key = RSA.import_key(encoded_key)
                data = input('data:\n').encode("utf-8")
                cipher_rsa = PKCS1_OAEP.new(key)
                enc = cipher_rsa.encrypt(data)
                with open(file_out, 'wb') as f: f.write(enc)
                return enc
            elif gen_or_encrypt_decrypt == 'd':
                file_in = input("file in:\n")
                private_key = RSA.import_key(open(file_name).read(), passphrase=passphrase)
                with open(file_in, 'rb') as f: data = f.read()
                cipher_rsa = PKCS1_OAEP.new(private_key)
                dec = cipher_rsa.decrypt(data)
                print(dec)
                return dec

    @staticmethod
    def visit_cryptography_DSA():
        print("Please note that this DSA implementation is using PyCryptodome")
        print("DSA is a public private key that can only be used for Signing and Verifying. It stands for Digital Signature Algorithm")
        user_input = input("Generate / Sign / Verify? G/S/V").lower()
        if user_input == 'g':
            Public_file_name = input("Public key file name (.pem will be appended): ") + '.pem'
            Private_file_name = input("Private key file name(.pem will be appended): ") + '.pem'
            passphrase = input("password: ")
            key = DSA.generate(2048)
            with open(Public_file_name, 'wb') as f:
                f.write(key.publickey().export_key(format="PEM"))
            with open(Private_file_name, 'wb') as f:
                f.write(key.export_key(format="PEM", passphrase=passphrase))
            return
        elif user_input == "s":
            message = input("message:\n").encode()
            Private_file_name = input("Private key file name(.pem will be appended): ") + '.pem'
            passphrase = input("password: ")
            with open(Private_file_name, 'r') as f:
                key = DSA.import_key(f.read(), passphrase)
            hash_obj = SHA256.new(message)
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(hash_obj)
            print(signature)
            signature_file_name = input("signature file name: ")
            with open(signature_file_name, 'wb') as f:
                f.write(signature)
            return
        elif user_input == 'v':
            Public_file_name = input("Public key file name (.pem will be appended): ") + '.pem'
            mess = input("message:\n").encode()
            signature_file_name = input("signature file name: ")
            with open(signature_file_name, 'rb') as f:
                signature = f.read()
            hash_obj = SHA256.new(mess)
            with open(Public_file_name, 'r') as f:
                pub_key = DSA.import_key(f.read())
            verifier = DSS.new(pub_key, 'fips-186-3')
            try:
                verifier.verify(hash_obj, signature)
                print("The message is authentic.")
            except ValueError:
                print("The message is not authentic.")

    @staticmethod
    def visit_cryptography_ChaCha20():
        print("Uses ChaCha20 from pycryptodome: 'https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20.html'")
        print("More info on ChaCha20: 'https://www.youtube.com/watch?v=UeIpq-C-GSA'")
        encrypt_or_decrypt = input("Encrypt or decrypt? E/D").lower()
        save_key_fn = input("key file name:")
        key = input("key: \n").encode()
        if len(key) == 0:
            load = input("load key? Y/N").lower()
            if load == 'y':
                with open(save_key_fn, 'rb') as f:
                    key = f.read()
            else:
                key = get_random_bytes(32)
        print(f"{key = }")
        with open(save_key_fn, 'wb') as f:
            f.write(key)
        if encrypt_or_decrypt == 'e':
            plaintext = input("plaintext: ").encode()
            cipher = ChaCha20.new(key=key)
            ciphertext = cipher.encrypt(plaintext)
            nonce = b64encode(cipher.nonce).decode('utf-8')
            ct = b64encode(ciphertext).decode('utf-8')
            result = json.dumps({'nonce': nonce, 'ciphertext': ct})
            print(result)
            return result
        elif encrypt_or_decrypt == 'd':
            b64 = input("json:\n")
            b64 = json.loads(b64)
            nonce = b64decode(b64['nonce'])
            ciphertext = b64decode(b64['ciphertext'])
            cipher = ChaCha20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            print(plaintext)
            return plaintext

    @staticmethod
    def visit_cryptography_AES_256():
        print("This uses Pycryptodome: 'https://pypi.org/project/pycryptodome/'")
        print("For more info about AES: 'https://www.youtube.com/watch?v=C4ATDMIz5wc&t=37s'")
        print("Using CBC")
        salt = input('salt:\n').encode()
        if len(salt) == 0:
            salt = get_random_bytes(32)
        print(f"{salt = }")
        passwd = input("password:\n")
        key = input("key:\n").encode()
        if len(key) == 0:
            im_key = input("import the key? Y/N").lower()
            if im_key in ['y', 'yes']:
                key_file_name = input("key file name: ")
                with open(key_file_name, 'rb') as f:
                    key = f.read()
            else:
                key = PBKDF2(passwd, salt, dkLen=32)
        print(f"{key = }")
        ex_key = input("export the key? Y/N").lower()
        if ex_key in ['y', 'yes']:
            key_file_name = input("key file name: ")
            with open(key_file_name, 'wb') as f:
                f.write(key)
        inp = input("Encrypt or decrypt? E/D").lower()
        filename = input("file name to save to:\n")
        if inp == 'e':
            message = input("Enter your message:\n").encode()
            cipher = AES.new(key, AES.MODE_CBC)
            ciphered_data = cipher.encrypt(pad(message, AES.block_size))
            print(ciphered_data)
            with open(filename, 'wb') as f:
                f.write(cipher.iv)
                f.write(ciphered_data)
            return
        elif inp == 'd':
            with open(filename, 'rb') as f:
                iv = f.read(16)
                data_to_be_decrypted_data = f.read()

            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            message = unpad(cipher.decrypt(data_to_be_decrypted_data), AES.block_size)
            print(message)


    #   ----Cryptography vulnerabilities start--------------


    @staticmethod
    def visit_cryptography_vuln_Fermat_Factorization():
        print("Fermat Factorization is a way to break weak rsa keys where the p and the q are too close together")
        print("With bigger keys this will take a long time, so I recommend you to try with small keys ")
        print("More info here: 'https://www.youtube.com/watch?v=-ShwJqAalOk'")
        n = int(input('N:\n'))
        t0 = math.isqrt(n) + 1
        counter = 0
        t = t0 + counter
        temp = math.isqrt((t * t) - n)
        while (temp * temp) != ((t * t) - n):
            counter += 1
            t = t0 + counter
            temp = math.isqrt((t * t) - n)
        s = temp
        p = t + s
        q = t - s
        if p == 1 or q == 1 or p * q != n:
            raise ValueError(f"something went wrong, {p * q == n = }")
        pn = (p - 1) * (q - 1)
        print(f"p: {p}\nq: {q}\nphi n: {pn}\n{n == p * q = }")
        e = int(input("Enter e:\n"))
        d = pow(e, -1, pn)
        print(f"{e = }")
        print(f"{d = }")
        return p, q, n, pn, e, d

    #   --------------Steganography start--------------

    @staticmethod
    def visit_steganography_PNG_LSB():
        hideorextract = input("Hide or extract? H/E:\n").lower()
        file_name = input("file name:")
        if hideorextract == 'h':
            msg = input("Message:\n")
            LSB.LSB.hide_message(msg, file_name)
            return
        elif hideorextract == 'e':
            msg = LSB.LSB.extract_msg(file_name)
            print(msg)
            return

    @staticmethod
    def visit_steganography_PNG_EOF():
        file_name = input("file name: ")
        file_name_out = input("file name out: ")
        hideorextract = input("Hide, extract, or delete? H/E/D:\n").lower()
        if hideorextract == 'd':
            EOF.PNGsSimple.del_message(file_name)
            return
        elif hideorextract == 'e':
            print(EOF.PNGsSimple.extract(file_name).decode())
            return
        elif hideorextract == 'h':
            EOF.PNGsSimple.add_message(input("Message:\n"), file_name, file_name_out)
    #   --------------Hashing start--------------

    @staticmethod
    def visit_hashing_Sha256():
        b = input("Message\n").encode()
        used_for_security = input("used for security? Y/N\n").lower()
        sha = hashlib.sha256(b, usedforsecurity=used_for_security in ['y'])
        type1 = input("hexdigest or digest? H/D\n").lower()
        if type1 == 'h':
            print(sha.hexdigest())
            return sha.hexdigest()
        elif type1 == 'd':
            print(sha.digest())
            return sha.digest()

    @staticmethod
    def visit_hashing_BLACK2b():
        b = input("Message\n").encode()
        h_obj = BLAKE2b.new(digest_bits=256)
        h_obj.update(b)
        type1 = input("hexdigest or digest? H/D\n").lower()
        if type1 == 'h':
            print(h_obj.hexdigest())
            return h_obj.hexdigest()
        elif type1 == 'd':
            print(h_obj.digest())
            return h_obj.digest()

    @staticmethod
    def visit_hashing_BLACK2s():
        b = input("Message\n").encode()
        h_obj = BLAKE2s.new(digest_bits=256)
        h_obj.update(b)
        type1 = input("hexdigest or digest? H/D\n").lower()
        if type1 == 'h':
            print(h_obj.hexdigest())
            return h_obj.hexdigest()
        elif type1 == 'd':
            print(h_obj.digest())
            return h_obj.digest()

    @staticmethod
    def visit_hashing_Sha512():
        b = input("Message\n").encode()
        used_for_security = input("used for security? Y/N\n").lower()
        sha = hashlib.sha512(b, usedforsecurity=used_for_security in ['y'])
        type1 = input("hexdigest or digest? H/D\n").lower()
        if type1 == 'h':
            print(sha.hexdigest())
            return sha.hexdigest()
        elif type1 == 'd':
            print(sha.digest())
            return sha.digest()

    @staticmethod
    def visit_hashing_Sha384():
        b = input("Message\n").encode()
        used_for_security = input("used for security? Y/N\n").lower()
        sha = hashlib.sha384(b, usedforsecurity=used_for_security in ['y'])
        type1 = input("hexdigest or digest? H/D\n").lower()
        if type1 == 'h':
            print(sha.hexdigest())
            return sha.hexdigest()
        elif type1 == 'd':
            print(sha.digest())
            return sha.digest()

    @staticmethod
    def visit_hashing_HMAC():
        print("Read more here: 'https://pycryptodome.readthedocs.io/en/latest/src/hash/hmac.html'")
        print("See more here: 'https://www.youtube.com/watch?v=wlSG3pEiQdc'")
        secret = input("secret\n").encode()
        msg = input("message:\n").encode()
        validate_or_create = input("verify auth? or create? V/C\n").lower()
        if validate_or_create == 'c':
            h = HMAC.new(secret, digestmod=SHA256)
            h.update(msg)
            print(h.hexdigest())
            return h.hexdigest()
        elif validate_or_create == 'v':
            mac = input("mac\n").encode()
            h = HMAC.new(secret, digestmod=SHA256)
            h.update(msg)
            try:
                h.hexverify(mac)
                print("The message '%s' is authentic" % msg)
            except ValueError:
                print("The message or the key is wrong")




    @staticmethod
    def visit_hashing_Sha224():
        b = input("Message\n").encode()
        used_for_security = input("used for security? Y/N\n").lower()
        sha = hashlib.sha224(b, usedforsecurity=used_for_security in ['y'])
        type1 = input("hexdigest or digest? H/D\n").lower()
        if type1 == 'h':
            print(sha.hexdigest())
            return sha.hexdigest()
        elif type1 == 'd':
            print(sha.digest())
            return sha.digest()


    @staticmethod
    def visit_hashing_Sha1():
        print('WARNING: Sha1 is known to be vulnerable to collisions!')
        print(
            """On 23 February 2017, the CWI (Centrum Wiskunde & Informatica) and Google announced the SHAttered attack, in which they generated two different PDF files with the same SHA-1 hash in roughly 263.1 SHA-1 evaluations.""")
        b = input("Message\n").encode()
        used_for_security = input("used for security? Y/N\n").lower()
        sha = hashlib.sha1(b, usedforsecurity=used_for_security in ['y'])
        type1 = input("hexdigest or digest? H/D\n").lower()
        if type1 == 'h':
            print(sha.hexdigest())
            return sha.hexdigest()
        elif type1 == 'd':
            print(sha.digest())
            return sha.digest()

    #   --------------My algs start--------------
    @staticmethod
    def visit_fun_algs_generate_cha_args():
        padding, shuffle_list = CHA.HashMaker.get_CHA_args()
        rev, slo0, smif0 = 4, 128, 128
        print(padding, shuffle_list, rev, slo0, smif0, sep='\n')
        return

    @staticmethod
    def visit_fun_algs_RA():
        print("More info on CHA: 'https://github.com/RoyNisimov1/CHA'")
        s = input("Message:\n")
        cha = CHA.CHAObject.RA(s)
        type1 = input("hexdigest or digest or num? H/D/N\n").lower()
        if type1 == 'h':
            print(cha.hexdigest())
            return cha.hexdigest()
        elif type1 == 'd':
            print(cha.digest())
            return cha.digest()
        elif type1 == 'n':
            print(cha.value)
            return cha.value

    @staticmethod
    def visit_fun_algs_CHAF_RAB():
        print("More info on CHA: 'https://github.com/RoyNisimov1/CHA'")

        def fRAB(b):
            return CHA.CHAObject.RAB(b)

        s = input("Message:\n")
        both_or_encrypt_or_decrypt = input("Encrypt, decrypt, or both. E/D/B:\n").lower()
        if both_or_encrypt_or_decrypt == 'e':
            obj = CHA.FeistelN().DE(s.encode(), 8, fRAB, 'e', 's')
            print(obj)
            return obj
        elif both_or_encrypt_or_decrypt == 'd':
            obj = CHA.FeistelN().DE(s, 8, fRAB, 'd', 's')
            print(obj.decode().strip())
            return obj
        elif both_or_encrypt_or_decrypt == 'b':
            e = CHA.FeistelN().DE(s.encode(), 8, fRAB, 'e', 's')
            print(e)
            d = CHA.FeistelN().DE(e, 8, fRAB, 'd', 's')
            print(d.decode().strip())
            return e, d.decode().strip()

    @staticmethod
    def visit_fun_algs_CHAF_RAB_With_Nonce():
        print("More info on CHA: 'https://github.com/RoyNisimov1/CHA'")
        nonce = input("nonce: ").encode()


        s = input("Message:\n")
        both_or_encrypt_or_decrypt = input("Encrypt, decrypt, or both. E/D/B:\n").lower()
        if both_or_encrypt_or_decrypt == 'e':
            key = input("HMAC key:\n").encode()
            h = CHA.CHAFHMAC(key, CHA.CHAObject.RAB)
            h.update(s.encode())
            mac = h.hexdigest()
            obj = CHA.FeistelN().DE(s.encode(), 8, CHA.FeistelN().fRAB_with_nonce(nonce), 'e', 's')
            print(obj)
            print(f"mac:\n{mac}")
            return obj
        elif both_or_encrypt_or_decrypt == 'd':
            mac = input("HMAC:\n")
            key = input("HMAC key:\n").encode()
            obj = CHA.FeistelN().DE(s, 8, CHA.FeistelN().fRAB_with_nonce(nonce), 'd', 's')
            h = CHA.CHAFHMAC(key, CHA.CHAObject.RAB)
            h.update(obj.strip())
            if h.verify(mac):
                print("The message '%s' is authentic" % obj.decode().strip())
            print(obj.decode().strip())
            return obj
        elif both_or_encrypt_or_decrypt == 'b':
            e = CHA.FeistelN().DE(s.encode(), 8, CHA.FeistelN().fRAB_with_nonce(nonce), 'e', 's')
            print(e)
            d = CHA.FeistelN().DE(e, 8, CHA.FeistelN().fRAB_with_nonce(nonce), 'd', 's')
            print(d.decode().strip())
            return e, d.decode().strip()

    @staticmethod
    def visit_fun_algs_CHAF_CHAB_With_Nonce():
        print("More info on CHA: 'https://github.com/RoyNisimov1/CHA'")
        padding = input("Padding:\n")
        shuffle = ast.literal_eval(input("Shuffle list:\n"))
        slo0 = int(input("Slo0:\n"))
        rep = int(input("Rep:\n"))
        char_set = input("Char set:\n")
        smi0 = int(input("Shift must if om0:\n"))
        rev_every = int(input("Reverse every:\n"))
        nonce = input("nonce: ").encode()

        def fCHAB(b):
            return CHA.FeistelN.fCHAB_with_nonce(nonce, padding, shuffle, slo0, rep, char_set, smi0, rev_every)(b)
        s = input("Message:\n")
        both_or_encrypt_or_decrypt = input("Encrypt, decrypt, or both. E/D/B:\n").lower()
        if both_or_encrypt_or_decrypt == 'e':
            key = input("HMAC key:\n").encode()
            h = CHA.CHAFHMAC(key, fCHAB)
            h.update(s.encode())
            mac = h.hexdigest()
            obj = CHA.FeistelN().DE(s.encode(), 8, fCHAB, 'e', 's')
            print(obj)
            print(f"mac:\n{mac}")
            return obj
        elif both_or_encrypt_or_decrypt == 'd':
            mac = input("HMAC:\n")
            key = input("HMAC key:\n").encode()
            obj = CHA.FeistelN().DE(s, 8, fCHAB, 'd', 's')
            h = CHA.CHAFHMAC(key, fCHAB)
            h.update(obj.strip())
            if h.verify(mac):
                print("The message '%s' is authentic" % obj.decode().strip())
            print(obj.decode().strip())
            return obj
        elif both_or_encrypt_or_decrypt == 'b':
            e = CHA.FeistelN().DE(s.encode(), 8, fCHAB, 'e', 's')
            print(e)
            d = CHA.FeistelN().DE(e, 8, fCHAB, 'd', 's')
            print(d.decode().strip())
            return e, d.decode().strip()

    @staticmethod
    def visit_fun_algs_CHA():
        print("More info on CHA: 'https://github.com/RoyNisimov1/CHA'")
        msg = input("Message:\n")
        padding = input("Padding:\n")
        shuffle = ast.literal_eval(input("Shuffle list:\n"))
        slo0 = int(input("Slo0:\n"))
        rep = int(input("Rep:\n"))
        char_set = input("Char set:\n")
        smi0 = int(input("Shift must if om0:\n"))
        rev_every = int(input("Reverse every:\n"))
        cha = CHA.CHAObject.CHA(msg, padding, shuffle, slo0, rep, char_set, smi0, rev_every)
        type1 = input("hexdigest or digest? H/D\n").lower()
        if type1 == 'h':
            print(cha.hexdigest())
            return cha.hexdigest()
        elif type1 == 'd':
            print(cha.digest())
            return cha.digest()

    @staticmethod
    def visit_fun_algs_BlackFrog():
        print("""BlackFrog is an asymmetric encryption that I invented (There might be a similar algorithm, the math is not very complicated.)""")
        print("""
            BlackFrog           
--------------------------------
          Key generation:
--------------------------------
Let p = large prime
Let q = large prime
Let n = p * q
Let e = 1 < e < n, gcd(e,n) = 1
Let d= e**-1 mod n 

Let r be 1<r<n-1
Let N be n * e * r * d

Public: e, N
Private: d, n

            Encryption
--------------------------------

c = m * e**e mod N

            Decryption
--------------------------------
m = c * d**e mod n


------------------------------------------------------------------------------------------------
This implementation uses OAEP

""")
        pub_file_name = input("Public file name: \n")
        priv_file_name = input("Private file name: \n")
        generate_encrypt_decrypt = input("Generate, Encrypt, Decrypt: G/E/D: \n").lower()
        if generate_encrypt_decrypt == 'g':
            pub, priv = BlackFrog.generate_keys(512)
            print(pub)
            print(priv)
            with open(pub_file_name, 'w') as f: f.write(pub.export())
            with open(priv_file_name, 'w') as f: f.write(priv.export())
            return
        elif generate_encrypt_decrypt == 'e':
            with open(pub_file_name, 'r') as f: pub = BlackFrogKey.load(f.read())
            msg = input("message:\n").encode()
            c = OAEP.OAEP.encrypt_BlackFrog(pub, msg)
            print(c)
            save_file = input("save file:\n")
            with open(save_file, 'wb') as f: f.write(c)
            return
        elif generate_encrypt_decrypt == 'd':
            with open(priv_file_name, 'r') as f: priv = BlackFrogKey.load(f.read())
            file_in = input("File input:\n")
            with open(file_in, 'rb') as f:
                cipher = f.read()
            msg = OAEP.OAEP.decrypt_BlackFrog(priv, cipher)
            print(msg.rstrip(b'\x00'))
            return

    @staticmethod
    def visit_fun_algs_CeaserCipher():
        print("Ceaser Cipher is also known as Rot13, it just shifts every letter in the alphabet forwards 13")
        en = string.ascii_lowercase + string.punctuation + string.digits
        en = list(en)
        shuffle = Common.shift_list(en.copy(), 13)
        encrypt_or_decrypt = input("Do you want to encrypt or decrypt? E/D").lower()
        if encrypt_or_decrypt == 'e':
            msg = input("message: ").lower()
            cipher = ''
            for ch in msg:
                index = en.index(ch)
                cipher += shuffle[index]
            print(cipher)
            return cipher
        elif encrypt_or_decrypt == 'd':
            cipher = input("message: ")
            msg = ''
            for ch in cipher:
                index = shuffle.index(ch)
                msg += en[index]
            print(msg)
            return msg
