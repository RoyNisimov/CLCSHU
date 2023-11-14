# <font size = 60 color=green>The Command Line Cryptography, Steganography and Hashing Utility </font>

**_Note that this tool was made purly for learning cryptography, python and for fun._**

<font size = 50 color=#e32709>**DO NOT USE FOR REAL USE CASES**</font>

# Installation

do ``` git clone https://github.com/RoyNisimov/CLCSHU```
then ``` cd CLCSHU```
and then do ```pip install -r requierments.txt```

# Using the tool
To use the tool simply run main.py.
Then you can follow the instructions.

# Contents

* [Terminology](#terminology)
* Tools
  * [Cryptography](#cryptography)
    * [Repeated Key Xor](#repeated-key-xor)
    * [Feistel64XOR](#feistel64xor)
    * [Fernet](https://cryptography.io/en/latest/fernet/)
    * [RSA](#rsa)
    * [AES - Computerphile](https://www.youtube.com/watch?v=O4xNJsjtN6E), [AES - Spanning Tree](https://www.youtube.com/watch?v=C4ATDMIz5wc)
    * [ChaCha20](https://www.youtube.com/watch?v=UeIpq-C-GSA)
    * [ElGamal](#elgamal)
    * [DSA](https://youtu.be/bO4lEQfPn60?t=386)
  * [Steganography](#steganography)
    * [PNGs](#pngs)
  * [Hashes](#hashes)
  * [Fun Algorithms](#fun-algorithms)

# Terminology

* **Plaintext** - The message in clear, before any manipulations.
* **Key** - The key that you use together with a function and plaintext.
* **Ciphertext** - The output of a funtion
* **Symmetric Encryption** - There is only one key that can both encrypt and decrypt
* **Asymmetric Encryption** - There are two keys, one encrypts and the other decrypts
* **Hash / Hash Digest** - A hash funtion is a function where you enter a message, 
and it spits out a digest. With a secure hash function getting the original message is close to impossible. 
Also note that the digest should be unique for every unique message but stay the same for the same message.
Read [Hashes](#hashes) for more info.
* **Nonce** - A nonce is an arbitrary number used only once in a cryptographic communication. They are often random or pseudo-random numbers.
* **IV** - IV stands for Initialization Vector. The IV is typically required to be random or pseudorandom, 
but sometimes an IV only needs to be unpredictable or unique.
* **Modes of operations** - check out [Modes of Operation - Computerphile](https://www.youtube.com/watch?v=Rk0NIQfEXBA)
* **^** - I will refer to the ^ operator as the [XOR function](#repeated-key-xor)
* **Pow / \*\*‎** - The power operator
* **Mod / %** - The remainder


## Cryptography

Right now the available algorithms in the cryptography section are:

* [Repeated Key Xor](#repeated-key-xor)
* [Byte To Int XOR](#byte-to-int-xor)
* [Feistel64XOR](#feistel64xor)
* [Fernet](https://cryptography.io/en/latest/fernet/)
* [RSA](#rsa)
* [AES - Computerphile](https://www.youtube.com/watch?v=O4xNJsjtN6E), [AES - Spanning Tree](https://www.youtube.com/watch?v=C4ATDMIz5wc)
* [ChaCha20](https://www.youtube.com/watch?v=UeIpq-C-GSA)
* [ElGamal](#elgamal)
* [DSA](https://youtu.be/bO4lEQfPn60?t=386)
* [SkipJack](https://www.youtube.com/watch?v=cMm5cd-WB2s)

Also note that some of the algorithms listed above are implemented using my code.

### Repeated key xor

XOR is a logic gate that is heavily used.

```
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


Repeated key xor is taking a plaintext and a key.
Foreach letter of the plaintext you xor the utf-8 charcter of the plaintext and the utf-8 charcter of the key
To decrypt do the samething with the ciphertext and the key

Ciphertext = Plaintext ^ Key
Plaintext = Ciphertext ^ Key

Example:

Plaintext = 'Hello world!'
Key = 'Key'

Xor:
'Hello world!' with
'KeyKeyKeyKey'
Get '030015270a593c0a0b270158' in hex

```
[Breaking repeating key XOR](https://dev.to/wrongbyte/cryptography-basics-breaking-repeated-key-xor-ciphertext-1fm2)

Python code:
```python
class XOR:
    @staticmethod
    def repeated_key_xor(plain_text, xor_key):
        pt = plain_text
        len_key = len(xor_key)
        encoded = []
        for i in range(0, len(pt)):
            encoded.append(pt[i] ^ xor_key[i % len_key])
        return bytes(encoded)
```

Source: [Encrypt using XOR Cipher with Repeating Key](https://www.geeksforgeeks.org/encrypt-using-xor-cipher-with-repeating-key/)

### Byte To Int XOR

Byte to Int XOR (I don't know the official name) is similar to the [Repeated key xor](#repeated-key-xor),
but it uses the ^ operator.

The implementation code
```python
import sys
class XOR:
    @staticmethod
    def xor(data, key):
        data_i = int.from_bytes(data, sys.byteorder)
        key_i = int.from_bytes(key, sys.byteorder)
        x = data_i ^ key_i
        x_byte = x.to_bytes(x.bit_length(), sys.byteorder).rstrip(b"\x00")
        return x_byte
```

### Feistel64XOR
Feistel64XOR is based on [Feistel Networks](https://www.youtube.com/watch?v=FGhj3CGxl8I).

The version that is used in here is my implementation.

```
A Feistel network is a symmetric encryption structure.


Plaintext: 'secret'
Key: 'secret key'

Pads the message to have 64 bits.
Then splits the message in two:
Left = paddedMessage[:32]
Right = paddedMessage[32:]

Works for n rounds:
{
    L   |   R   
    |       |
   XOR(R, L) <-- XOR(R, Key)
    |       |
  Swap L and R
}
 Swap L and R
Ciphertext = L | R

In this case the ciphertext is: 
'7365637265742020202020202020202020202020202020202020202020202020202020202020206b6579736563726574206b6579736563726574206b65797365'
```

### RSA

RSA is an asymmetric encryption, RSA stands for Rivest–Shamir–Adleman. 
It was invented in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman.
``` 
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

```

### ElGamal
ElGamal is an asymmetric encryption invented by Taher Elgamal in 1985.
```
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

The message is authentic
```
The implementation here (not in the math explanation) uses OAEP (commonly used with RSA). All ElGamal implementation in here was written by me, including the OAEP




## Steganography
Right now the available formats in the steganography section are:
  - [PNGs](#pngs)

### PNGs
Right now the available algorithms in the steganography-PNGs section are:
  - [PNG EOF](#eof), [PNG EOF video](https://youtu.be/_DhqDYLS8oY?t=76)
  - [Least Significant Bit](#lsb), [LSB Video](https://youtu.be/_DhqDYLS8oY?t=580)

There is a StegExample file for you to try

#### EOF
EOF stands for End Of File. It just means that you append the message bytes to the end of the png file

#### LSB
LSB stands for Least Significant Bit.

You take a message and for each byte of the picture you change the least significant bit of byte and change it to a bit of the message

## Hashes
Hashing is the process of transforming any given key or a string of characters into another value. 

This is usually represented by a shorter, fixed-length value or key that represents and makes it easier to find or employ the original string.

The most popular use for hashing is the implementation of hash tables.

## Fun Algorithms
Some of the algorithms here were invented by me. 

everything here is purly for fun and for the challenge of creating something myself.

Available algorithms in this section:

- My algorithms
  - [CHA](#cha)
  - [Generate CHA](#generate-cha)
  - [RA (Hash)](#ra)
  - [Feistel cipher RAB](#feistel-cipher-rab)
  - [Feistel cipher RAB with nonce](#feistel-cipher-rab-with-nonce)
  - [CHAB Feistel](#chab-feistel)
  - [BlackFrog](#blackfrog)
- Encryption algs:
 - [Ceaser-Cipher / Rot13](#ceaser-cipher--rot13)

### My Algorithms
- [CHA](#cha)
- [Generate CHA](#generate-cha)
- [RA (Hash)](#ra)
- [Feistel cipher RAB](#feistel-cipher-rab)
- [Feistel cipher RAB with nonce](#feistel-cipher-rab-with-nonce)
- [CHAB Feistel](#chab-feistel)
- [BlackFrog](#blackfrog)

* #### CHA
  CHA stands for Customizable Hashing Algorithm.
  
  CHA is a hashing algorithm that takes a lot of parameters
  
  Read more about CHA [here](https://github.com/RoyNisimov1/CHA)

* #### Generate CHA
  Generate some of the needed CHA parameters

* #### RA
  RA is an already configured CHA algorithm
* #### Feistel cipher RAB
  Feistel cipher RAB is a symmetric encryption that uses the [Feistel Network](#feistel64xor) along with RAB (RA Bytes).
  Since the 'Key' of the funtion is the RAB function, everyone can decrypt it.
* #### Feistel cipher RAB with nonce
  Feistel cipher RAB with nonce is a symmetric encryption that uses the [Feistel Network](#feistel64xor) along with RAB (RA Bytes).
  and a secret key (The nonce)
* #### CHAB Feistel
  CHAB Feistel is a symmetric encryption that uses the [Feistel Network](#feistel64xor) along with CHAB (CHA Bytes).
  and a secret key (The nonce)
* #### BlackFrog
  BlackFrog is an asymmetric encryption that I invented/found. (The math is not very complicated, so I won't be surprised if someone else had already discovered it)
  Also note that this encryption is not safe at all.
  The math of BlackFrog is as follows:
  ``` 
  Key generation:
  —---------------------------------------------------------------

  Let n = large prime number

  Pick e such that gcd(e,n) == 1 and e < n and e is prime
  d = e**-1 % n
  N = n * e * random
  E = e**d % N
  D = d**d % n

  Public key: {E,N}
  Private key: {n,d,e,D}
  
  (Note that the signing is basicly RSA)
  
  Encryption:
  —---------------------------------------------------------------

  ciphertext = message*E % N

  Decryption:
  —---------------------------------------------------------------
  message = ciphertext*D % n

  Known problams:
  This is probably insecure.
  
  
  
  
  ```
  Please keep in mind that things might change.

  Also, this implementation uses OAEP and the key size is 512.

### Encryption algs
- #### Ceaser Cipher / Rot13
  This cipher shifts the letters of the alphabet by 13
