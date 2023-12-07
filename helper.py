import sys
import random
from main import Bcolors
import CHA
from CHA import BlackFrog, BlackFrogKey, OAEP, Piranha
import string
import hashlib
import ast
import math
from cryptography.fernet import Fernet
from Steganography.PNGs import LSB
from Steganography.PNGs import EOF
from my_cryptography import ElGamal, OAEP, Skipjack, MorseCode, BaseConverter
from my_cryptography.Global import Common
from Exeptions import InputException
import json
# pycryptodome:
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20, DES, Blowfish
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
        if to_call is None: raise Exception(f"No method named {method_name} found in the {branch_name} branch name!")
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
    def visit_cryptography_DES():
        print(f"{Bcolors.FAIL}DES (Data Encryption Standard) is considered broken and shouldn't really be used anymore. Use AES instead.{Bcolors.ENDC}")
        print(f"{Bcolors.FAIL}This uses the Pycryptodome single DES implementation{Bcolors.ENDC}")
        user_input = input("Encrypt, decrypt. E/D: ").lower()
        key = input("8 bit key: ")
        if 8 > len(key) > 0:
            key += ' ' * (8 - len(key))
        if len(key) > 8: key = key[:8]
        key = key.encode()
        if user_input == 'e':
            cipher = DES.new(key, DES.MODE_OFB)
            plaintext = pad(input("Message: ").encode(), DES.block_size)
            c = cipher.iv + cipher.encrypt(plaintext)
            file_out = input("File out: ")
            with open(file_out, "wb") as f: f.write(c)
            return c
        elif user_input == 'd':
            file_in = input("File in: ")
            with open(file_in, 'rb') as f:
                iv = f.read(8)
                encrypted = f.read()
            cipher = DES.new(key, DES.MODE_OFB, iv=iv)
            plain = unpad(cipher.decrypt(encrypted), DES.block_size)
            print(plain)
            return plain
        else:
            raise InputException("Input can be E or D! ")

    @staticmethod
    def visit_cryptography_Blowfish():
        print(f"{Bcolors.FAIL}Blowfish is deemed secure and it is fast. However, its keys should be chosen to be big enough to withstand a brute force attack (e.g. at least 16 bytes). Use AES instead.{Bcolors.ENDC}")
        user_input = input("Encrypt, decrypt. E/D: ").lower()
        key = input("16 bit key: ").encode()
        if user_input == 'e':
            cipher = Blowfish.new(key, Blowfish.MODE_CBC)
            plaintext = input("Message: ").encode()
            plaintext = pad(plaintext, Blowfish.block_size)
            msg = cipher.iv + cipher.encrypt(plaintext)
            file = input("File out: ")
            with open(file, 'wb') as f:
                f.write(msg)
        elif user_input == 'd':
            file = input("File in: ")
            with open(file, 'rb') as f:
                iv = f.read(8)
                c = f.read()
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
            packed_msg = cipher.decrypt(c)
            unpacked_msg = unpad(packed_msg, Blowfish.block_size)
            print(unpacked_msg)
            return unpacked_msg


    @staticmethod
    def visit_cryptography_ElGamal():
        print(f"""{Bcolors.FAIL}{Bcolors.BOLD}WARNING: This is my implementation of ElGamal and OAEP, probably not the safest! Also note that RSA is considered a better asymmetric encryption.
Also the key exportation is using my code with my algorithm (Not safe!).
{Bcolors.ENDC}""")
        print(f"""{Bcolors.FAIL}{Bcolors.BOLD}WARNING: ElGamal encryption is being used, but this is probably not safe here because it's my code.
Again, if this is for real use-cases use something else
{Bcolors.ENDC}""")
        modes = ['Use', 'Info']
        for index, name in enumerate(modes):
            print("{0}: {1}".format(index, name))
        index = int(input("Enter choice number: "))
        to_call = modes[index % len(modes)]
        if to_call == 'Use':
            pub_key = input("Public file name (.pem will be appended):\n") + '.pem'
            priv_key = input("Private file name (.pem will be appended):\n") + '.pem'
            user_input = input("Generate, encrypt, decrypt, sign, verify? G/E/D/S/V: ").lower()
            if user_input == "g":
                size = input("size? default is 1024 (not secure enough)")
                if len(size) == 0: size = 1024
                else:
                    size = int(size)
                pub, priv = ElGamal.ElGamal.generate_keys(size)
                print(f'{pub = }\n{priv = }')
                passcode = input("passcode: ").encode()
                key = priv.export_key(passcode)
                with open(priv_key, 'wb') as f:
                    f.write(key)
                key = pub.export_key()
                with open(pub_key, 'wb') as f:
                    f.write(key)
                return
            elif user_input == "e":
                with open(pub_key, 'rb') as f:
                    key = ElGamal.ElGamalKey.import_key(f.read())
                print(key)
                m = input('message:\n').encode('utf-8')
                c1, c2 = OAEP.OAEP.encrypt_ElGamal(key, m)
                print(c1)
                print(c2)
                file_out = input('file out: ')
                edata = {"c1": c1, "c2": c2}
                with open(file_out, 'w') as f:
                    f.write(json.dumps(edata, indent=2))
                return c1, c2
            elif user_input == "d":
                passcode = input("Passcode: ").encode()
                with open(priv_key, 'rb') as f:
                    key = ElGamal.ElGamalKey.import_key(f.read(), passcode)
                print(key)
                file_in = input('file in:\n')
                with open(file_in, 'r') as f:
                    edata = json.loads(f.read())
                m = OAEP.OAEP.decrypt_ElGamal(key, edata["c1"], edata["c2"])
                print(m.rstrip(b'\x00'))
                return m
            elif user_input == 's':
                passcode = input("Passcode: ").encode()
                with open(priv_key, 'rb') as f:
                    key = ElGamal.ElGamalKey.import_key(f.read(), passcode)

                msg = input("Message: ").encode()
                m, s1, s2 = ElGamal.ElGamal.sign(key, msg)
                print(f"{Bcolors.OKGREEN}{m = }\n{s1 = }\n{s2 = }{Bcolors.ENDC}")
                file_out = input("File out: ")
                data = {"m": m, "s1": s1, 's2': s2}
                with open(file_out, 'w') as f:
                    f.write(json.dumps(data, indent=2))
                return m, s1, s2
            elif user_input == 'v':
                with open(pub_key, 'rb') as f:
                    key = ElGamal.ElGamalKey.import_key(f.read())
                file_name = input('File in:\n')
                with open(file_name, 'r') as f:
                    vdata = json.loads(f.read())
                ver = ElGamal.ElGamal.verify(key, vdata['m'], vdata['s1'], vdata['s2'])
                if ver:
                    print(f"{Bcolors.OKGREEN}Message is verified!{Bcolors.ENDC}")
                else: print(f"{Bcolors.FAIL}Message is not authentic!{Bcolors.ENDC}")
                return ver



        elif to_call == 'Info':
            print("""The ElGamal cryptosystem was invented in 1985, by Taher Elgamal.
                        The math of ElGamal
------------------------------------------------------------------------

                          Key Generation
------------------------------------------------------------------------
Let p = large prime number
Let g = 1 < g < p-1
Let x = 1 < x < p-1
Let y = g**x % p

Public = {p,g,y}
Private = {x}

                            Encryption
------------------------------------------------------------------------

m = message < p
Let b = 2 < b < p-1
C1 = g**b % p
C2 = (m * y**b) % p

                            Decryption
------------------------------------------------------------------------

XM = C1**x % p
m = (C2 * XM**(p-2)) % p

                             Signing
------------------------------------------------------------------------
m = message
k = 0 < k < p
s1 = g**k % p
phi = p - 1
mod_inv = k ** -1 % phi // pow(k, -1, phi)
s2 = (mod_inv * (m - x * s1)) % phi

Send {m, s1, s2}
Keep k private

                             Verifying
------------------------------------------------------------------------
V = y**s1 * s1**s2 % p
W = g**m % p
If V == W then the message was signed by the private key



                              Example
------------------------------------------------------------------------

Let p = 23
Let g = 6
Let x = 8
Let y = 6**8 % 23 = 18

m = 4
Let b = 3
C1 = 6**3 % 23 = 9
C2 = (4 * 18**3) % 23 = 6

XM = 9**8 % 23 = 13
m = (6 * 13**21) % 23 = 4

Sign 
m = 5
k = 3
s1 = g**k % m = 9
phi_n = p-1 = 22
inv = k**-1 % phi_n = 15
s2 = (inv * (m - x * s1)) % phi_n = 7

Verify
V = (18**9 * 9**7) % 23 = 2
W = 6**5 % 23 = 2

W == V: True 
The message is authentic
------------------------------------------------------------------------

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
            result = json.dumps({'nonce': nonce, 'ciphertext': ct}, indent=2)
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
        print("Fermat Factorization is a way to break weak RSA keys where the p and the q are too close together")
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

    @staticmethod
    def visit_cryptography_vuln_known_message_XOR():
        print(f"{Bcolors.BOLD}{Bcolors.UNDERLINE}Before we begin, please use repeated key XOR{Bcolors.ENDC}")
        print(f"{Bcolors.BOLD}{Bcolors.UNDERLINE}{Bcolors.OKGREEN}This method does XOR with the ciphertext and the message to get the key{Bcolors.ENDC}")
        print(f"{Bcolors.BOLD}{Bcolors.UNDERLINE}{Bcolors.FAIL}You might get more than one key, for example if your message was 'test' and the key was 'key', the cipher text will be '1f000a1f' in bytes. But after running through the function the key is going to be 'keyk'{Bcolors.ENDC}")
        c1 = bytes.fromhex(input("Cipher: "))
        m = input("Message: ").encode()
        key = Common.repeated_key_xor(m, c1).decode()
        print(f"{Bcolors.OKGREEN}The key is: '{key}'{Bcolors.ENDC}")
        return key

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
    def visit_fun_algs_CHAF_RAB_With_Nonce_OAEP():
        print("More info on CHA: 'https://github.com/RoyNisimov1/CHA'")
        nonce = input("nonce: ").encode()
        s = input("Message:\n")
        both_or_encrypt_or_decrypt = input("Encrypt, decrypt, or both. E/D/B:\n").lower()
        if both_or_encrypt_or_decrypt == 'e':
            key = input("HMAC key:\n").encode()
            h = CHA.CHAFHMAC(key, CHA.CHAObject.RAB)
            h.update(s.encode())
            mac = h.hexdigest()
            padded = OAEP.OAEP.oaep_pad(s.encode())
            obj = CHA.FeistelN().DE(padded, 8, CHA.FeistelN().fRAB_with_nonce(nonce), 'e', 's')
            print(obj)
            print(f"mac:\n{mac}")
            return obj
        elif both_or_encrypt_or_decrypt == 'd':
            mac = input("HMAC:\n")
            key = input("HMAC key:\n").encode()
            obj = CHA.FeistelN().DE(s, 8, CHA.FeistelN().fRAB_with_nonce(nonce), 'd', 's')
            h = CHA.CHAFHMAC(key, CHA.CHAObject.RAB)
            obj = OAEP.OAEP.oaep_unpad(obj).rstrip(b"\x00")
            h.update(obj)
            if h.verify(mac):
                print(f"{Bcolors.OKGREEN}The message '{obj.decode()}' is authentic{Bcolors.ENDC}")
            else:
                print(f"{Bcolors.FAIL}{Bcolors.BOLD}The message '{obj.decode()}' is not authentic{Bcolors.ENDC}")
            print(obj.decode())
            return obj
        elif both_or_encrypt_or_decrypt == 'b':
            padded = OAEP.OAEP.oaep_pad(s.encode())
            e = CHA.FeistelN().DE(padded, 8, CHA.FeistelN().fRAB_with_nonce(nonce), 'e', 's')
            print(e)
            d = CHA.FeistelN().DE(e, 8, CHA.FeistelN().fRAB_with_nonce(nonce), 'd', 's')
            d = OAEP.OAEP.oaep_unpad(d).rstrip(b"\x00")
            print(d.decode())
            return e, d.decode()

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
        print(f"""{Bcolors.WARNING}BlackFrog is probably not safe{Bcolors.ENDC}""")
        print(f"""{Bcolors.FAIL}{Bcolors.BOLD}The PEM exporting is my code, and my algorithm. again, this isn't secure!{Bcolors.ENDC}""")
        print(f"{Bcolors.UNDERLINE}{Bcolors.BOLD}Please note that the signing and verifying is just RSA{Bcolors.ENDC}")
        pub_file_name = input("Public file name (.pem will be appended) : \n") + '.pem'
        priv_file_name = input("Private file name (.pem will be appended): \n") + '.pem'
        generate_encrypt_decrypt = input("Generate, Encrypt, Decrypt: G/E/D: \n").lower()
        if generate_encrypt_decrypt == 'g':
            pub, priv = BlackFrog.generate_keys(1024)
            print(pub)
            print(priv)
            passcode = input("Passcode: ").encode()
            with open(pub_file_name, 'wb') as f: f.write(pub.export())
            with open(priv_file_name, 'wb') as f: f.write(priv.export(passcode))
            return
        elif generate_encrypt_decrypt == 'e':
            with open(pub_file_name, 'rb') as f: pub = BlackFrogKey.load(f.read())
            msg = input("message:\n").encode()
            c = OAEP.OAEP.encrypt_BlackFrog(pub, msg)
            print(c)
            save_file = input("save file:\n")
            with open(save_file, 'wb') as f: f.write(c)
            return
        elif generate_encrypt_decrypt == 'd':
            passcode = input("Passcode: ").encode()
            with open(priv_file_name, 'rb') as f: priv = BlackFrogKey.load(f.read(), passcode)
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
        encrypt_or_decrypt = input("Do you want to encrypt or decrypt? E/D: ").lower()
        if encrypt_or_decrypt == 'e':
            msg = input("message: ").lower()
            cipher = ''
            for ch in msg:
                index = en.index(ch)
                cipher += shuffle[index]
            print(cipher)
            return cipher
        elif encrypt_or_decrypt == 'd':
            cipher = input("cipher: ")
            msg = ''
            for ch in cipher:
                index = shuffle.index(ch)
                msg += en[index]
            print(msg)
            return msg

    @staticmethod
    def visit_fun_algs_ADD():
        print(f"{Bcolors.OKBLUE}Turns your message into int, adds the key as int. returns the bytes{Bcolors.ENDC}")
        key = input("key: ").encode()
        key_int = int.from_bytes(key, sys.byteorder)
        encrypt_or_decrypt = input("Do you want to encrypt or decrypt? E/D: ").lower()
        if encrypt_or_decrypt == 'e':
            msg = input("message: ").encode()
            m_int = int.from_bytes(msg, sys.byteorder)
            cipher = m_int + key_int
            print(cipher)
            return cipher
        elif encrypt_or_decrypt == 'd':
            cipher = input("cipher: ")
            m_int = int(cipher)
            cipher = m_int - key_int
            b = cipher.to_bytes(cipher.bit_length(), sys.byteorder).rstrip(b'\x00')
            print(b)
            return b
        else:
            raise InputException("Input can be E/D!")

    @staticmethod
    def visit_fun_algs_MUL():
        print(f"{Bcolors.OKBLUE}Turns your message into int, multiply the key as int. returns the bytes{Bcolors.ENDC}")
        key = input("key: ").encode()
        key_int = int.from_bytes(key, sys.byteorder)
        encrypt_or_decrypt = input("Do you want to encrypt or decrypt? E/D: ").lower()
        if encrypt_or_decrypt == 'e':
            msg = input("message: ").encode()
            m_int = int.from_bytes(msg, sys.byteorder)
            cipher = m_int * key_int
            print(cipher)
            return cipher
        elif encrypt_or_decrypt == 'd':
            cipher = input("cipher: ")
            m_int = int(cipher)
            cipher = int(m_int // key_int)
            b = cipher.to_bytes(cipher.bit_length(), sys.byteorder).rstrip(b'\x00')
            print(b)
            return b

    @staticmethod
    def visit_fun_algs_BASE64():
        print(f"{Bcolors.OKBLUE}This uses the built in python base64{Bcolors.ENDC}")
        encrypt_or_decrypt = input("Do you want to encrypt or decrypt? E/D: ").lower()
        if encrypt_or_decrypt == 'e':
            msg = input("message: ").encode()
            cipher = b64encode(msg)
            print(cipher)
            return cipher
        elif encrypt_or_decrypt == 'd':
            cipher = input("cipher: ")
            msg = b64decode(cipher)
            print(msg)
            return msg

    @staticmethod
    def visit_fun_algs_Binary():
        encrypt_or_decrypt = input("Do you want to encrypt or decrypt? E/D: ").lower()
        if encrypt_or_decrypt == 'e':
            msg = input("message: ")
            cipher = " ".join([format(ord(c), 'b') for c in msg])
            print(cipher)
            return cipher
        elif encrypt_or_decrypt == 'd':
            cipher = input("cipher: ")
            msg = ''.join([chr(int(c, 2)) for c in cipher.split(" ")])
            print(msg)
            return msg

    @staticmethod
    def visit_fun_algs_Shuffle():
        english = list(string.ascii_letters + string.punctuation + string.digits)
        encrypt_or_decrypt = input("Do you want to generate, encrypt or decrypt? G/E/D: ").lower()
        if encrypt_or_decrypt == 'g':
            file_name = input('File name: ')
            new1 = english.copy()
            random.shuffle(new1)
            print(new1)
            date = {"key": new1}
            with open(file_name, 'w') as f: f.write(json.dumps(date, indent=2))
        elif encrypt_or_decrypt == 'e':
            file_name = input('Key file name: ')
            with open(file_name, 'r') as f: data = json.loads(f.read())
            msg = input('message: ')
            cipher = ''
            for i, c in enumerate(msg):
                index = english.index(c)
                cipher += data['key'][index]
            print(cipher)
            return cipher
        elif encrypt_or_decrypt == 'd':
            file_name = input('Key file name: ')
            with open(file_name, 'r') as f:
                data = json.loads(f.read())
            cipher = input("Cipher: ")
            msg = ''
            for i, c in enumerate(cipher):
                index = data['key'].index(c)
                msg += english[index]
            print(msg)
            return msg

    @staticmethod
    def visit_fun_algs_MorseCode():
        encrypt_or_decrypt = input("Do you want to encrypt or decrypt? E/D: ").lower()
        if encrypt_or_decrypt == 'e':
            msg = input("message: ")
            split = input("split: space or newline? S/N: ").lower()
            if split == "s": split = ' '
            elif split == 'n': split = "\n"
            else: raise InputException("Input is not S or N!")
            cipher = MorseCode.MorseCode.encrypt(msg, split)
            print(cipher)
            return cipher
        elif encrypt_or_decrypt == 'd':
            cipher = input("cipher: ")
            split = input("split: space or newline? S/N: ").lower()
            if split == "s":
                split = ' '
            elif split == 'n':
                split = "\n"
            else:
                raise InputException("Input is not S or N!")
            msg = MorseCode.MorseCode.decrypt(cipher, split)
            print(msg)
            return msg

    @staticmethod
    def visit_fun_algs_BaseConverter():
        encrypt_or_decrypt = input("Do you want to Base10 to base ?, Base ? to base 10, base ?1 to base ?2, B10/TB10/BB: \n").lower()
        if encrypt_or_decrypt == 'b10':
            msg = input("message: ").encode()
            base = int(input("Base: "))
            character_sheet = None
            if base >= 16:
                character_sheet = input("character sheet: ")
            msg_int = Common.bti(msg)
            final = BaseConverter.BaseConverter.convertFromBase10(msg_int, base, character_sheet)
            print(final)
            return final
        elif encrypt_or_decrypt == 'tb10':
            cipher = input("cipher: ")
            base = int(input("Base: "))
            character_sheet = None
            if base >= 16:
                character_sheet = input("character sheet: ")
            final = BaseConverter.BaseConverter.to_dec(cipher, base, character_sheet)
            final = Common.itb(final)
            print(final)
            return final
        elif encrypt_or_decrypt == 'bb':
            msg = input("message: ")
            base1 = int(input("Base1: "))
            base2 = int(input("Base2: "))
            character_sheet1 = None
            if base1 > 64:
                character_sheet1 = input("character sheet1: ")
            character_sheet2 = None
            if base2 > 64:
                character_sheet2 = input("character sheet2: ")
            final = BaseConverter.BaseConverter.base_to_base(msg, base1, base2, character_sheet1, character_sheet2)
            print(final)
            return final
        else:
            raise InputException("Invalid Input! input can be: 'B10', 'TB10' or 'BB'")

    @staticmethod
    def visit_fun_algs_ElGamal():
        print(f"{Bcolors.WARNING}I'm also putting ElGamal here because it's using my code and the exportation is using my algorithm. (Probably not secure){Bcolors.ENDC}")
        Call.visit_cryptography_ElGamal()
        return

    @staticmethod
    def visit_fun_algs_Piranha():
        print(
            f"{Bcolors.WARNING}This is my encryption algorithm, more info here: 'https://github.com/RoyNisimov1/CHA'{Bcolors.ENDC}")
        encrypt_or_decrypt = input(
            "Encrypt, decrypt. E/D: \n").lower()
        modeOfOperation = input("Mode of operation, ECB/CBC/CTR: ").lower()
        key = input('Key: ').encode()
        if encrypt_or_decrypt == 'e':
            msg = Piranha.pad(input('Message: ').encode(), Piranha.BlockSize)
            if modeOfOperation == 'ecb':
                cipher = Piranha(key, Piranha.ECB, data=msg)
                c = cipher.encrypt()
                print(c)
                file = input("File: ")
                with open(file, 'wb') as f: f.write(cipher.HMAC() + c)
                return c
            if modeOfOperation == 'cbc':
                cipher = Piranha(key, Piranha.CBC, data=msg)
                c = cipher.encrypt(msg)
                print(cipher.iv + c)
                file = input("File: ")
                with open(file, 'wb') as f: f.write(cipher.HMAC() + cipher.iv + c)
                return c
            if modeOfOperation == 'ctr':
                cipher = Piranha(key, Piranha.CTR, data=msg)
                c = cipher.encrypt(msg)
                print(cipher.iv + c)

                file = input("File: ")
                with open(file, 'wb') as f: f.write(cipher.HMAC() + cipher.iv + c)
                return c

        elif encrypt_or_decrypt == 'd':
            msg = Piranha.pad(input('Original message (For HMAC ): ').encode(), Piranha.BlockSize)

            file = input("File: ")
            if modeOfOperation == 'ecb':
                cipher = Piranha(key, Piranha.ECB, data=msg)
                with open(file, 'rb') as f:
                    hmac = f.read(64)
                    data = f.read()
                d = Piranha.unpad(cipher.decrypt(data))
                print(d)
                v = cipher.verify(msg, hmac)
                if v: print(f"{Bcolors.OKGREEN}The message is authentic{Bcolors.ENDC}")
                else: print(f"{Bcolors.FAIL}The message isn't authentic{Bcolors.ENDC}")
                return d
            if modeOfOperation == 'cbc':
                with open(file, 'rb') as f:
                    hmac = f.read(64)
                    iv = f.read(16)
                    data = f.read()
                cipher = Piranha(key, Piranha.CBC, iv=iv)
                d = Piranha.unpad(cipher.decrypt(data))
                print(d)
                cipher.update(d)
                v = cipher.verify(msg, hmac)
                if v:
                    print(f"{Bcolors.OKGREEN}The message is authentic{Bcolors.ENDC}")
                else:
                    print(f"{Bcolors.FAIL}The message isn't authentic{Bcolors.ENDC}")
                return d
            if modeOfOperation == 'ctr':
                with open(file, 'rb') as f:
                    hmac = f.read(64)
                    iv = f.read(16)
                    data = f.read()
                cipher = Piranha(key, Piranha.CTR, iv=iv)
                d = Piranha.unpad(cipher.decrypt(data))
                print(d)
                cipher.update(d)
                v = cipher.verify(msg, hmac)
                if v:
                    print(f"{Bcolors.OKGREEN}The message is authentic{Bcolors.ENDC}")
                else:
                    print(f"{Bcolors.FAIL}The message isn't authentic{Bcolors.ENDC}")
                return d

        else:
            raise InputException("Invalid Input! input can be: ECB/CBC/CTR")

    @staticmethod
    def visit_fun_algs_Hex():
        print(f"Turns bytes into hex and hex to bytes")
        encrypt_or_decrypt = input("Encrypt, decrypt. E/D: \n").lower()
        if encrypt_or_decrypt == 'e':
            msg = input("Message: ").encode().hex()
            print(msg)
            return msg
        if encrypt_or_decrypt == 'd':
            msg = bytes.fromhex(input("Cipher: "))
            print(msg)
            return msg
        else:
            raise InputException("Input can be E/D")
