from hashlib import sha256, shake_256
from random import Random

FLAG = b'DH{This_is_fake_flag}'

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def long_to_bytes(n):
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

M = 79228162514264337593667407189
m = [536870923, 536871931, 536872957, 536873959, 536874991, 536876009, 536877013, 536878049, 536879059, 536880071, 536881087, 536882239]
d = 47893489367115774634385277346838405874917158424435934
tau = M // 8 - 1337
rng = Random(828927513140)
moduli = [M * x for x in m]

def circular_distance(a, b, M):
    d = (a - b) % M
    if d > M // 2:
        d -= M
    return d

while True:
    Q1 = rng.randrange(1, d - 1)
    Q2 = rng.randrange(1, d - 1)
    if Q1 == Q2:
        continue
    ok = True
    for mod in m:
        a = Q1 % mod
        b = Q2 % mod
        if min(a, mod - 1 - a, b, mod - 1 - b) < 64:
            ok = False
            break
    if ok:
        break

while True:
    rc1 = rng.randrange(M)
    delta = rng.randrange(M // 4, M // 2)
    rc2 = (rc1 + delta) % M
    cd = abs(circular_distance(rc1, rc2, M))
    if M // 4 <= cd <= M // 2:
        break

pairs = []
for mi, Mk in zip(m, moduli):
    q1 = Q1 % mi
    q2 = Q2 % mi
    base1 = q1 * M + rc1
    base2 = q2 * M + rc2
    while True:
        e1 = rng.randrange(-tau, tau + 1)
        t1 = base1 + e1
        if 0 <= t1 < Mk:
            break
    while True:
        e2 = rng.randrange(-tau, tau + 1)
        t2 = base2 + e2
        if 0 <= t2 < Mk:
            break
    pair = [t1, t2]
    rng.shuffle(pair)
    pairs.append(pair)

nonce = bytes.fromhex("b16b00b5cafef00d")
qmin, qmax = sorted((Q1, Q2))
key = sha256(long_to_bytes(qmin) + b"|" + long_to_bytes(qmax)).digest()
ciphertext = xor_bytes(FLAG, shake_256(key + nonce).digest(len(FLAG)))

print(f"moduli = {moduli}")
print(f"pairs = {pairs}")
print(f"nonce = {nonce.hex()}")
print(f"ciphertext = {ciphertext.hex()}")