import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import easygui
from art import *

os.system('color 2')
tprint('Select option')

salt = b"+fiTD*Xsa-LEB9[^rm#Wo}Yvgy)CR>8GQbqAF<_w~ePcZ2u!@H04MnklSUN5d$]"


def encrypt():
    try:
        os.system('cls')
        tprint('Encrypt file')
        file_path = easygui.fileopenbox()
        print(f'File path: {file_path}')
        print()

        with open(file_path, 'rb') as f:
            data = f.read()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )

        password = bytes(getpass.getpass('Password: '),'utf-8')
        # text = bytes(input('Enter text: '), 'utf-8')
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        encrypt_text = f.encrypt(data)
        ret = encrypt_text.decode('utf-8')

        # wWrite the encrypted file
        with open(f'{file_path}.enc', 'wb') as f:
            f.write(encrypt_text)

        file_name = str(file_path).split('\\')[-1]
        file_extention = str(str(file_path).split('\\')[-1]).split('.')[1]
        print(f'{file_name} encrypt complet.')
        print(f'New file {file_name}.{file_extention}.k1e')
        tprint('complet!')
    except:
        print('Oops! Error')


def decrypt():
    try:
        os.system('cls')
        os.system('color 3')   
        tprint('Decrypt file')
        file_path = easygui.fileopenbox()
        print(f'File path: {file_path}')
        print()

        with open(file_path, 'rb') as f:
            data = f.read()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )

        password = bytes(getpass.getpass('Password: '),'utf-8')
        # text = bytes(input('Enter text: '), 'utf-8')
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)

        decrypt = f.decrypt(data)
        # ret = decrypt.decode('utf-8')



        path = str(file_path).split('\\')[:-1]
        path = '\\'.join(path)
        file_name = str(str(file_path).split('\\')[-1]).split('.')[0]
        file_extention = str(str(file_path).split('\\')[-1]).split('.')[1] = str(str(file_path).split('\\')[-1]).split('.')[1]

        # wWrite the encrypted file
        with open(f'{path}\\{file_name}.{file_extention}', 'wb') as f:
            f.write(decrypt)

        print(f'{file_name} decrypt complet.')
        print(f'New file {file_name}.{file_extention}')
        tprint('complet!')
    except:
        print('Oops! Error')


option = input('\n1-Encrypt\n2-Decrypte\n\nSelect Options: ')
print('-'*17)

if option == '1': #Encrypt
    encrypt()
    input('Press Enter to exit')
elif option == '2': #Decrypt
    decrypt()
    input('Press Enter to exit')

