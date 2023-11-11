

class PNGsSimple:
    END_HEX = b"\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82"

    def __init__(self):
        pass

    @staticmethod
    def add_message(message: str, filename: str, new_file_name=None):
        if new_file_name is None:
            new_file_name = filename
        with open(filename, 'rb') as f:
            content = f.read()
        with open(new_file_name, 'wb') as f:
            f.write(content + message.encode())

    @staticmethod
    def del_message(filename):
        with open(filename, 'r+b') as f:
            content = f.read()
            offset = content.index(PNGsSimple.END_HEX)
            f.seek(offset + len(PNGsSimple.END_HEX))
            to_remove = f.read()
        make_content = content.strip(to_remove)
        with open(filename, 'wb') as f:
            f.write(make_content)

    @staticmethod
    def extract(filename: str):
        with open(filename, 'rb') as f:
            content = f.read()
            offset = content.index(PNGsSimple.END_HEX)
            f.seek(offset + len(PNGsSimple.END_HEX))
            return f.read()




