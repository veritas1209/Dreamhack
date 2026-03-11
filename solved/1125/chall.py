import hashlib
import os

K = os.urandom(500)
flag = open("flag.txt", "r").read()

def HMAC(M):
    return hashlib.md5(K + M).digest()

m1 = b"Dreamhack"
h1 = HMAC(m1)

print(f"HMAC(\"Dreamhack\") = {bytes.hex(h1)}")

m2 = bytes.fromhex(input("Your message: "))
h2 = bytes.fromhex(input("Your hash: "))

if m2 != m1 and h2 == HMAC(m2):
    print(flag)