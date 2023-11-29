import argparse
from helper import *
class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
if __name__ == '__main__':
    banner = f"""{Bcolors.OKCYAN}
___________.__              _________                                                .___ .__   .__                   
\\__    ___/|  |__    ____   \\_   ___ \\   ____    _____    _____  _____     ____    __| _/ |  |  |__|  ____    ____    
  |    |   |  |  \\ _/ __ \\  /    \\  \\/  /  _ \\  /     \\  /     \\ \\__  \\   /    \\  / __ |  |  |  |  | /    \\ _/ __ \\   
  |    |   |   Y  \\  ___/  \\     \\____(  <_> )|  Y Y  \\|  Y Y  \\ / __ \\_|   |  \\/ /_/ |  |  |__|  ||   |  \\  ___/   
  |____|   |___|  / \\___  >  \\______  / \\____/ |__|_|  /|__|_|  /(____  /|___|  /\\____ |  |____/|__||___|  / \\___  >  
                \\/      \\/          \\/               \\/       \\/      \\/      \\/      \\/                 \\/      \\/   
_________                            __                                            .__                                
\\_   ___ \\ _______  ___.__.______  _/  |_   ____     ____  _______ _____   ______  |  |__   ___.__.                   
/    \\  \\/ \\_  __ \\<   |  |\\____ \\ \\   __\\ /  _ \\   / ___\\ \\_  __ \\__  \\  \\____ \\ |  |  \\ <   |  |                   
\\     \\____ |  | \\/ \\___  ||  |_> > |  |  (  <_> ) / /_/  > |  | \\/ / __ \\_|  |_> >|   Y  \\ \\___  |                   
 \\______  / |__|    / ____||   __/  |__|   \\____/  \\___  /  |__|   (____  /|   __/ |___|  / / ____| /\\                
        \\/          \\/     |__|                   /_____/               \\/ |__|         \\/  \\/      )/                
  _________  __                                                                             .__                ____   
 /   _____/_/  |_   ____     ____  _____     ____    ____     ____  _______ _____   ______  |  |__   ___.__.  /  _ \\  
 \\_____  \\ \\   __\\_/ __ \\   / ___\\ \\__  \\   /    \\  /  _ \\   / ___\\ \\_  __ \\__  \\  \\____ \\ |  |  \\ <   |  |  >  _ </\\
 /        \\ |  |  \\  ___/  / /_/  > / __ \\_|   |  \\(  <_> ) / /_/  > |  | \\/ / __ \\_|  |_> >|   Y  \\ \\___  | /  <_\\ \\/
/_______  / |__|   \\___  > \\___  / (____  /|___|  / \\____/  \\___  /  |__|   (____  /|   __/ |___|  / / ____| \\_____\\ \\
        \\/             \\/ /_____/       \\/      \\/         /_____/               \\/ |__|         \\/  \\/             \\/
  ___ ___                  .__     .__                    ____ ___   __   .__ .__   .__   __                          
 /   |   \\ _____     ______|  |__  |__|  ____     ____   |    |   \\_/  |_ |__||  |  |__|_/  |_  ___.__.               
/    ~    \\__  \\   /  ___/|  |  \\ |  | /    \\   / ___\\  |    |   /\\   __\\|  ||  |  |  |\\   __\\<   |  |               
/    ~    \\__  \\   /  ___/|  |  \\ |  | /    \\   / ___\\  |    |   /\\   __\\|  ||  |  |  |\\   __\\<   |  |               
\\    Y    / / __ \\_ \\___ \\ |   Y  \\|  ||   |  \\ / /_/  > |    |  /  |  |  |  ||  |__|  | |  |   \\___  |               
 \\___|_  / (____  //____  >|___|  /|__||___|  / \\___  /  |______/   |__|  |__||____/|__| |__|   / ____|               
       \\/       \\/      \\/      \\/          \\/ /_____/                                          \\/                    
{Bcolors.ENDC}"""

    def print_list(list_name):
        for index, name in enumerate(list_name):
            print(f"{index}: {Bcolors.OKGREEN}{name}{Bcolors.ENDC}")
        index = int(input("Enter choice number: "))
        is_dict = isinstance(list_name, dict)
        if is_dict:
            return list(list_name.values())[index % len(list_name)]
        return list_name[index % len(list_name)]

    argspars = argparse.ArgumentParser()
    argspars.add_argument("-b", '--branch', type=str, help="The branch of the tool, can be c,s,h,f")
    args = argspars.parse_args()
    print(banner)
    print(
        f"{Bcolors.WARNING}WARNING: This tool was just for fun and learning. In real use cases use something that you know is 100% safe")
    print(f"WARNING: Some of the tools only have ECB mode! check out more info about modes of operation: 'https://www.youtube.com/watch?v=Rk0NIQfEXBA'{Bcolors.ENDC}")
    print(f"{Bcolors.FAIL}This tool was made for fun and learning cryptography and python. {Bcolors.BOLD}DO NOT USE FOR REAL USE CASES{Bcolors.ENDC}")
    print("banner was made with this: 'https://patorjk.com/software/taag/#p=display&h=0&v=0&f=Graffiti&t=Type%20Something%20'")
    cryptography_modes = ['cryptography', "vulnerabilities"]
    cryptography_list = ['repeated_key_xor', 'ByteToIntXOR', 'Feistel64XOR', 'Fernet', 'RSA', "AES_256", "DES", "ChaCha20",
                         "ElGamal", "DSA", "Skipjack"]
    cryptography_vuln = {"Fermat Factorization (In RSA)": "Fermat_Factorization", "Known message XOR attack": "known_message_XOR"}
    steganography = ["PNG_LSB", "PNG_EOF"]
    hashing = ['Sha256', 'Sha512', 'Sha1', 'Sha384', "Sha224", "BLACK2s", "BLACK2b", "HMAC"]
    fun_algs = {"CHA (Hash)": "CHA", "Generate CHA": "generate_cha_args", 'RA (Hash)': "RA",
                "Feistel cipher RAB (Symmetric encryption with preset key)": "CHAF_RAB",
                "Feistel cipher RAB with nonce (Symmetric encryption with preset key and password)": "CHAF_RAB_With_Nonce",
                "Feistel cipher RAB with nonce and OAEP (Symmetric encryption with preset key and password and OAEP padding)": "CHAF_RAB_With_Nonce_OAEP",
                "CHA Feistel (Symmetric encryption with a custom key and password)": "CHAF_CHAB_With_Nonce",
                "BlackFrog (Asymmetric encryption)": "BlackFrog", "Ceaser-Cipher / Rot13": "CeaserCipher", "ADD": "ADD",
                "MUL": "MUL", "Base 64": "BASE64", "Binary / Base 2": "Binary", "Base Converter": "BaseConverter", "Shuffle": "Shuffle", "Morse Code": "MorseCode", "ElGamal": "ElGamal"}
    call = Call()
    if args.branch == 'c':
        branch = 'cryptography'
        c = print_list(cryptography_modes)
        index = cryptography_modes.index(c)
        if index == 0:
            c = print_list(cryptography_list)
            call.visit(branch, c)
        elif index == 1:
            branch += '_vuln'
            c = print_list(cryptography_vuln)
            call.visit(branch, c)
    elif args.branch == 's':
        branch = 'steganography'
        c = print_list(steganography)
        call.visit(branch, c)
    elif args.branch == 'h':
        branch = 'hashing'
        print(
            """Hashing is used in many parts of cryptography. It's a way of storing a fingerprint of the data but not the actual data.""")
        c = print_list(hashing)
        call.visit(branch, c)
    elif args.branch == 'f':
        print("WARNING: not for real use cases, this was made for fun!")
        branch = 'fun_algs'
        c = print_list(fun_algs)
        call.visit(branch, c)
    else:
        csh: str = input(f"""{Bcolors.HEADER}1) Cryptography
2) Steganography
3) Hashing
4) Fun Algorithms (WARNING: not for real use cases){Bcolors.ENDC}
""")
        branch = ''

        if csh == '1':
            branch = 'cryptography'
            c = print_list(cryptography_modes)
            index = cryptography_modes.index(c)
            if index == 0:
                c = print_list(cryptography_list)
                call.visit(branch, c)
            elif index == 1:
                branch += '_vuln'
                c = print_list(cryptography_vuln)
                call.visit(branch, c)
        elif csh == '2':
            branch = 'steganography'
            c = print_list(steganography)
            call.visit(branch, c)
        elif csh == '3':
            branch = 'hashing'
            print(
                """Hashing is used in many parts of cryptography. It's a way of storing a fingerprint of the data but not the actual data.""")
            c = print_list(hashing)
            call.visit(branch, c)
        elif csh == '4':
            print("WARNING: not for real use cases, this was made for fun!")
            branch = 'fun_algs'
            c = print_list(fun_algs)
            call.visit(branch, c)
