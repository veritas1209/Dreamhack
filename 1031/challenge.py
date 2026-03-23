from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from collections import namedtuple
import os

# Tonelli-Shanks algorithm
# From: https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#Python
def legendre(a, p):
    return pow(a, (p - 1) // 2, p)

def tonelli(n, p):
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r
# Tonelli-Shanks algorithm end

p = 419987277261396331
a, b = 267849768333949543, 190288349752338993
Point = namedtuple('Point', ['x', 'y'])

def rand(lim):
    blen = (lim.bit_length() + 7) // 8
    return int.from_bytes(os.urandom(blen), 'big') % lim

def random_point():
    while True:
        x = rand(p - 1) + 1
        y2 = x ** 3 + a * x + b
        if legendre(y2, p) == 1:
            y = tonelli(y2, p)
            return Point(x, y)

def inverse(a):
    return pow(a, p - 2, p)

def add(P, Q):
    if P is None and Q is None:
        return None
    elif P is None:
        return Q
    elif Q is None:
        return P

    if P.x == Q.x and P.y == Q.y:
        lam = (3 * P.x ** 2 + int(a)) * inverse(2 * P.y) % p
    elif P.x == Q.x:
        return None
    else:
        lam = (Q.y - P.y) * inverse(Q.x - P.x) % p

    x = (lam ** 2 - P.x - Q.x) % p
    y = (lam * (P.x - x) - P.y) % p 

    return Point(x, y)

def mul(P, k):
    base, ret = P, None
    while k > 0:
        if k & 1:
            ret = add(ret, base)
        k >>= 1
        base = add(base, base)
    return ret

key = 0
for idx in range(4096):
    P = random_point()
    k = rand(2 ** 56)
    Q = mul(P, k)
    key ^= (k << (8 * (idx % 10)))

    print(f"P_{idx}: {P}")
    print(f"Q_{idx}: {Q}")

with open('flag.txt', 'rb') as f:
    flag = f.read()

key = key.to_bytes(16, 'big')
cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(flag, 16))

print(ct.hex())
