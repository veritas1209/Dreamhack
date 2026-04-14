from Crypto.Util.number import getPrime, long_to_bytes, isPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from secret import FLAG
import os
import signal

signal.alarm(60)

small_factors = [2, 3, 5, 7, 11, 13, 17, 19]
M = 1
for x in small_factors:
    M *= x

while True:
    q = getPrime(256)
    p = M * q + 1
    if isPrime(p):
        break

while True:
    h = 2 + (int.from_bytes(os.urandom(16), "big") % (p - 3))
    g = pow(h, q, p)
    if g == 1:
        continue

    ok = True
    for r in small_factors:
        if pow(g, M // r, p) == 1:
            ok = False
            break
    if ok:
        break

a = int.from_bytes(os.urandom(32), "big") % M
A = pow(g, a, p)

server_secret = int.from_bytes(os.urandom(32), "big") % M
server_pub = pow(g, server_secret, p)

final_shared = pow(server_pub, a, p)
final_key = sha256(long_to_bytes(final_shared)).digest()[:16]
iv = os.urandom(16)
ct = AES.new(final_key, AES.MODE_CBC, iv).encrypt(pad(FLAG, 16))

print("=== 룸의정석 ===")
print("룸과 룸 사이의 비밀 대화를 위해 키를 교환합니다.")
print("상대가 보낸 공개키를 믿고 안전한 대화를 시작해보세요.")
print()
print(f"p = {p}")
print(f"g = {g}")
print(f"A = {A}")
print(f"server_pub = {server_pub}")
print()

MENU = """[1] send public key
[2] get encrypted message
[3] quit"""

for _ in range(40):
    print(MENU)
    try:
        cmd = int(input("> ").strip())
    except:
        print("bye")
        break

    if cmd == 1:
        try:
            B = int(input("B = ").strip())
        except:
            print("invalid")
            continue

        if not (2 <= B < p):
            print("invalid")
            continue

        shared = pow(B, a, p)
        tag = sha256(long_to_bytes(shared)).hexdigest()
        print(f"tag = {tag}")

    elif cmd == 2:
        print(f"iv = {iv.hex()}")
        print(f"ciphertext = {ct.hex()}")

    else:
        print("bye")
        break