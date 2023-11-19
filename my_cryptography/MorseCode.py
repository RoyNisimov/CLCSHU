




class MorseCode:
    MORSECODE = morse_code = {"A": "*-", "B": "-***"
                 , "C": "-*-*", "D": "-**", "E": "*",
                 "F": "**-*", "G": "--*", "H": "****", "I": "**"
                 , "J": "*---", "K": "-*-", "L": "*-**", "M": "--",
                "N": "-*", "O": "---", "P": "*--*", "Q": "--*-", "R": "*-*", "S": "***", "T": "-", "U": "**-", "V": "***-", "W": "*--", "X": "-**-", "Y": "-*--", "Z": "--**"
                , "1": "*----", "2": "**---", "3": "***--", "4": "****-", "5": "*****", "6": "-****", "7": "--***", "8": "---**", "9": "----*", "0": "-----"}

    @staticmethod
    def encrypt(message: str, split: str):
        message = message.upper()
        l = [MorseCode.MORSECODE[c] for c in message]
        return split.join(l)

    @staticmethod
    def decrypt(cipher: str, split: str):
        l = cipher.split(split)
        m = ''
        for c in l:
            m += list(MorseCode.MORSECODE.keys())[list(MorseCode.MORSECODE.values()).index(c)]
        return m
