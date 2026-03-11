#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from os import urandom

class LCG:
    BITS = 1024
    MOD = 2 ** BITS
    TRUNC = 512

    def __init__(self):
        self.mult = int.from_bytes(urandom(self.BITS // 8), 'big') | 1
        self.value = int.from_bytes(urandom(self.BITS // 8), 'big')
    
    def next(self):
        self.value = self.mult * self.value % self.MOD
        return self.value >> self.TRUNC

def main():
    lcg = LCG()

    with open("values", "w") as f:
        cnt = 0
        while cnt < 10000:
            value = lcg.next()
            if urandom(1)[0] & 1:
                cnt += 1
                f.write(str(value) + '\n')

    key = sha256(lcg.next().to_bytes(512 // 8, 'big')).digest()
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    with open("flag", "rb") as f:
        flag = f.read()

    encrypted = cipher.encrypt(pad(flag, 16))

    with open("enc", "wb") as f:
        f.write(iv)
        f.write(encrypted)

if __name__ == "__main__":
    main()