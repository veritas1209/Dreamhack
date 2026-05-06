#! /usr/bin/env python3
import os
from cipher import TinyGHOST
from utils import *


def menu() -> int:
    print('1. encrypt')
    print('2. flag')
    print('3. exit')
    return int(input('> '))

if __name__ == '__main__':
    with open('flag', 'rb') as f:
        flag = f.read()

    key = os.urandom(4)
    g = TinyGHOST(key)

    while True:    
        i = menu()
        if i == 1:
            msg = input('plaintext(hex)> ')
            enc = g.encrypt(bytes.fromhex(msg))
            print('ciphertext(hex)>', enc.hex())
        elif i == 2:
            new_key = xor_bytes(key, bytes.fromhex('deadbeef'))
            new_g = TinyGHOST(new_key)
            enc_flag = new_g.encrypt(flag)
            print('encrypted_flag(hex)> ', enc_flag.hex())
        else:
            break
