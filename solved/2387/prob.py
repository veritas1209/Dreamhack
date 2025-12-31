from Crypto.Util.number import getPrime, bytes_to_long
from math import gcd
from secret import flag
import random

def level3():
    r, n = [], 1

    while len(r) < 21:
        p = getPrime(96)
        if p & 3 == 3:      
            r.append(p)
            n = n * p

    m = bytes_to_long(flag)
    c = pow(m, 2, n)

    return n, c, r

def level2(r):
    e, r_c, r_n = 65537, [], []

    for i in range(0, len(r), 3):   
        p, q, m = r[i], r[i+1], r[i+2]
        if gcd(e, (p-1)*(q-1)) != 1:
            print(':(')
            exit(0)
        
        n = p * q
        c = pow(m, e, n)
        r_c.append(c)
        r_n.append(n)

    return r_n, r_c

def level1(r_n, r_c):
    x1, x2 = [], []
    for i in range(len(r_n)):
        a = random.getrandbits(r_n[i].bit_length())
        b = a ^ r_n[i]
        x1.append(r_c[i] ^ a)
        x2.append(r_c[i] ^ b)
    return x1, x2

n, c, r = level3()
r_n, r_c = level2(r)
x1, x2 = level1(r_n, r_c)

print("Level 1:")
print(f'{x1 = }')
print(f'{x2 = }')
print(f'{r_c = }')

print("\nLevel 2:")
print("e = 65537")

print("\nLevel 3:")
print(f"{n = }")
print(f"{c = }")
