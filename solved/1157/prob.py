#! /usr/bin/env python3
import os
from cipher import ARIA

def menu():
    print('1. Encrypt with 3-round ARIA')
    print('2. Encrypt with Any-round ARIA')
    print('3. Flag')
    print('4. Exit')

if __name__ == '__main__':
    with open('flag', 'rb') as f:
        flag = f.read()

    key = os.urandom(16)
    aria_3 = ARIA(key, 3)
    eks = aria_3.ek

    while True:
        menu()
        i = int(input('> '))
        if i == 1:
            msg = input('plaintext(hex)> ')
            enc = aria_3.encrypt(bytes.fromhex(msg))
            print('ciphertext(hex)>', enc.hex())
        elif i == 2:
            eks3 = input('eks[3](hex)> ')
            if bytes.fromhex(eks3) == eks[3]:
                r = int(input('round(1~16)> '))
                aria_r = ARIA(key, r)
                msg = input('plaintext(hex)> ')
                enc = aria_r.encrypt(bytes.fromhex(msg))
                print('ciphertext(hex)>', enc.hex())
            else:
                print('To use this feature, obtain `eks[3]` first')
        elif i == 3:
            enc_flag = aria_3.encrypt(flag)
            print('encrypted_flag(hex)>', enc_flag.hex())
        else:
            break
