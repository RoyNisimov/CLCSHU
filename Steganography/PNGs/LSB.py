import numpy as np
import PIL.Image

class LSB:
    def __init__(self):
        pass

    @staticmethod
    def hide_message(message: str, filename: str, stop_indicator='$STOP$'):
        image = PIL.Image.open(filename, 'r')
        width, height = image.size
        img_arr = np.array(list(image.getdata()))
        if image.mode == 'P':
            raise TypeError("Type not supported!")
        channels = 4 if image.mode == 'RGBA' else 3
        pixels = img_arr.size // channels
        stop_indicator_length = len(stop_indicator)
        message += stop_indicator

        byte_msg = ''.join(f"{ord(c):08b}" for c in message)
        bits = len(byte_msg)

        if bits > pixels:
            raise Exception("Not enough space!")

        index = 0
        for i in range(pixels):
            for j in range(0,3):
                if index < bits:
                    img_arr[i][j] = int(bin(img_arr[i][j])[2:-1] + byte_msg[index], 2)
                    index += 1
        img_arr = img_arr.reshape((height, width, channels))
        result = PIL.Image.fromarray(img_arr.astype('uint8'), image.mode)
        result.save('Encoded' + filename)

    @staticmethod
    def extract_msg(filename: str, stop_indicator='$STOP$'):
        image = PIL.Image.open(filename, 'r')
        img_arr = np.array(list(image.getdata()))
        if image.mode == 'P':
            raise TypeError("Type not supported!")
        channels = 4 if image.mode == 'RGBA' else 3
        pixels = img_arr.size // channels
        secret_bits = [bin(img_arr[i][j])[-1] for i in range(pixels) for j in range(0, 3)]
        secret_bits = ''.join(secret_bits)
        secret_bits = [secret_bits[i:i+8] for i in range(0, len(secret_bits), 8)]

        secret_msg = [chr(int(secret_bits[i], 2)) for i in range(len(secret_bits))]
        secret_msg = ''.join(secret_msg)
        if stop_indicator in secret_msg:
            return secret_msg[:secret_msg.index(stop_indicator)]
        else:
            raise Exception(f"No message found! {stop_indicator = }")

