#!/usr/bin/env python3
# requires: pwntools, gmpy2, pycryptodome
import re
from math import gcd
from functools import reduce
from fractions import Fraction
import gmpy2
from gmpy2 import mpz
from pwn import remote, args, context
from Crypto.Util.number import bytes_to_long, isPrime

context.log_level = 'info'
HOST, PORT = args.HOST or '127.0.0.1', int(args.PORT or 1337)
io = remote("host3.dreamhack.games", 12422)

# ---------- IO ----------
def init():
    io.recvuntil(b' > ')                     # banner + first prompt

def snacks(k):                               # action 1, returns list of c_i (mpz)
    io.sendline(b'1')
    io.recvuntil(b'for Amo? > ')
    io.sendline(str(k).encode())
    data = io.recvuntil(b' > ')              # "Great snack.." + dummies + next prompt
    hx = re.findall(rb'0x([0-9a-fA-F]+)', data)
    assert len(hx) == k, (len(hx), k)
    return [mpz(int(h, 16)) for h in hx]

def cook(inp):                               # action 2
    io.sendline(b'2')
    io.recvuntil(b' > ')
    io.sendline(str(inp).encode())
    return io.recvall(timeout=10)

# ---------- finite differences ----------
def multi_diff_int(cs, ts, D):               # exact integer Delta^D c_t for each t in ts
    accs = [mpz(0)] * len(ts); accs = [mpz(0) for _ in ts]
    bc = mpz(1)
    for j in range(D + 1):
        neg = (D - j) & 1
        for idx, t in enumerate(ts):
            term = bc * cs[t + j]
            accs[idx] = accs[idx] - term if neg else accs[idx] + term
        bc = bc * (D - j) // (j + 1)
    return accs

def diff_modN(cs, t, D, N, inv):             # Delta^D c_t mod N (cheap)
    res = 0; bc = 1
    for j in range(D + 1):
        term = bc * (int(cs[t + j]) % N) % N
        res = (res - term) % N if (D - j) & 1 else (res + term) % N
        bc = bc * ((D - j) % N) % N * inv[j + 1] % N
    return res % N

# ---------- 2D Gauss reduction ----------
def gauss(v1, v2):
    dot = lambda a, b: a[0]*b[0] + a[1]*b[1]
    while True:
        if dot(v2, v2) < dot(v1, v1):
            v1, v2 = v2, v1
        m = round(Fraction(dot(v1, v2), dot(v1, v1)))
        if m == 0:
            return v1, v2
        v2 = (v2[0] - m*v1[0], v2[1] - m*v1[1])

# ================= exploit =================
init()
M = 65546
cs = snacks(65536) + snacks(M - 65536)       # c_0 .. c_{M-1}
n_total = M

# 1) N 복구
D_N = M - 6                                  # > e  보장 (e <= 65521)
vals = multi_diff_int(cs, [0, 1, 2, 3, 4], D_N)
N = reduce(gcd, [int(v) for v in vals])
for p in range(2, 1 << 16):                  # 코팩터에서 생긴 작은 소인수 제거 (실제 N=pq엔 없음)
    while N % p == 0 and N // p > 1 and (N // p).bit_length() > 2000:
        N //= p
N = int(N)
assert 2040 <= N.bit_length() <= 2050 and all(int(c) < N for c in cs)
print(f"[+] N ({N.bit_length()} bit) recovered")

# 2) e 복구
inv = [0] * (M + 2)
for i in range(1, M + 2):
    inv[i] = int(gmpy2.invert(i, N))
is_zero = lambda d: diff_modN(cs, 0, d, N, inv) == 0 and diff_modN(cs, 1, d, N, inv) == 0
lo, hi = 1, M - 2
assert is_zero(hi)
while lo < hi:
    mid = (lo + hi) // 2
    if is_zero(mid): hi = mid
    else:            lo = mid + 1
e = lo - 1
assert isPrime(e) and e.bit_length() == 16
print(f"[+] e = {e}")

# 3) a/b mod N  ->  4) 격자로 a, b
alpha = diff_modN(cs, 0, e - 1, N, inv)
beta  = diff_modN(cs, 0, e,     N, inv)
r = (alpha * int(gmpy2.invert(beta, N)) - (e - 1) // 2) % N

v1, v2 = gauss((1, int(r)), (0, N))
c0 = int(cs[0] % N)
a = b = None
for (X, Y) in (v1, v2):
    for s in (1, -1):
        bb, aa = s * X, s * Y
        if aa > 0 and bb > 0 and pow(aa, e, N) == c0:
            a, b = aa, bb
assert a and b and isPrime(b)
print(f"[+] dummy1(init)={a}\n[+] dummy2={b}")

# 5) action 2
T = bytes_to_long(b'SUPER_DELICIOUS_FLAG_FOR_YOU')
np_ = n_total + (n_total & 1)                # 짝수로 (b-1의 인수 2 회피)
while gcd(a + np_ * b, b - 1) != 1:
    np_ += 2
extra = np_ - n_total
while extra > 0:                             # 지수 보정용 추가 snack
    k = min(extra, 65536); snacks(k); extra -= k; n_total += k

E1 = a + np_ * b                             # 현재 dummy1
inp = pow(T, pow(E1, -1, b - 1), b)
assert pow(inp, E1, b) == T
print(cook(inp).decode(errors='replace'))