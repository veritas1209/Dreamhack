from sage.all import *
import os, random, hashlib

P = 2^31 - 1
F = GF(P)
d, t, n = 20, 10, 64

R.<x> = PolynomialRing(F)
coeffs = [F.random_element() for _ in range(d+1)]
f = sum(coeffs[i] * x^i for i in range(d+1))

xs = random.sample(range(1, 10^6), n)
ys = [int(f(F(xi))) for xi in xs]

bad_idx = random.sample(range(n), t)
for i in bad_idx:
    ys[i] = random.randrange(P)

packed = b"".join(int(c).to_bytes(4, "big") for c in coeffs)
seed_int = int.from_bytes(hashlib.sha256(packed).digest(), "big")
random.seed(seed_int)

BITS = 512
mk = lambda: (random.getrandbits(BITS) | (1<<(BITS-1)) | 1)
p = next_prime(mk())
q = next_prime(mk())
while p == q:
    q = next_prime(mk())

N = p * q
e = 65537

flag = b"DH{" + os.urandom(16).hex().encode() + b"}"
m = int.from_bytes(flag, "big")
c = pow(m, e, N)

print("xs =", xs)
print("ys =", ys)
print("N =", N)
print("e =", e)
print("c =", c)

