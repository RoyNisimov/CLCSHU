import base64
from math import log
import string
# https://www.youtube.com/watch?v=s3mxIcr7fOQ

class BaseConverter:
    @staticmethod
    def convertFromBase10(num, base, baseCharSet=None):
        if baseCharSet is None: baseCharSet = "0123456789" + string.ascii_letters + "+/"
        assert base <= len(baseCharSet)
        numToChar = {i: baseCharSet[i] for i in range(len(baseCharSet))}
        power = int(log(num, base))
        converted = ""
        for pow1 in range(power, -1, -1):
            p = pow(base, pow1)
            converted += numToChar[num // p]
            num %= p
        return converted

    @staticmethod
    def to_dec(num, base, baseCharSet=None):
        if baseCharSet is None: baseCharSet = "0123456789" + string.ascii_letters + "+/"
        assert base <= len(baseCharSet)
        numToChar = {baseCharSet[i]: i for i in range(len(baseCharSet))}
        n = 0
        num = num[::-1]
        for i, p in enumerate(num):
            n += pow(base, i) * numToChar[p]
        return n

    @staticmethod
    def base_to_base(num, base1, base2, baseCharSet1=None, baseCharSet2=None):
        first = BaseConverter.to_dec(num, base1, baseCharSet1)
        return BaseConverter.convertFromBase10(first, base2, baseCharSet2)

