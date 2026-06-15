from Crypto.Util.number import *
import os

BITS = 512
ORACLE = BITS // 4

def randbits(bits):
    blen = (bits + 7) // 8
    num = int.from_bytes(os.urandom(blen), 'little')
    return num >> (blen * 8 - bits)

def gen_params():
    p_lsb = int(input('p_lsb > '))
    q_lsb = int(input('q_lsb > '))

    assert p_lsb.bit_length() <= ORACLE
    assert q_lsb.bit_length() <= ORACLE

    e = 0x10001

    while True:
        p = p_lsb + (randbits(BITS - ORACLE) << ORACLE)
        q = q_lsb + (randbits(BITS - ORACLE) << ORACLE)
        if not isPrime(p) or not isPrime(q):
            continue
        
        phi = (p - 1) * (q - 1)
        if GCD(phi, e) != 1:
            continue

        n = p * q
        d = inverse(e, phi)
        return n, e, d

def print_flag():
    with open("./flag", "r") as f:
        print(f.read())

n, e, d = gen_params()
target = randbits(2 * BITS) % n

print(f"n: {n}")
print(f"enc(target): {pow(target, e, n)}")

while True:
    c = int(input("c > "))
    if c == target:
        print("Impressive...")
        print_flag()
        exit(0)

    m = pow(c, d, n)

    o = (m >> ORACLE) & 1
    print(f"o: {o}")
