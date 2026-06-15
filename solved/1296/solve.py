#!/usr/bin/env python3
import os, re, sys, time
from Crypto.Util.number import isPrime
from fpylll import IntegerMatrix, LLL
from gf2bv import LinearSystem
from gf2bv.crypto.mt import MT19937
from pwn import remote, process, context

context.log_level = 'info'
BLEN = 256
N = 24                          # number of Put samples (>=22 for unique MT state)
TARGET = 0x13371337

def next_prime(p):
    p |= 1
    while not isPrime(p): p += 2
    return p

Q = next_prime(2 ** BLEN)       # Q is a PUBLIC deterministic constant

def recover_p(es):
    n, RHO = 12, 456            # noise Q*r ~ 456 bits
    M = IntegerMatrix(n, n); M[0, 0] = 2 ** (RHO + 1)
    for i in range(1, n):
        M[0, i] = es[i]; M[i, i] = -es[0]
    LLL.reduction(M)
    q0 = abs(M[0, 0]) >> (RHO + 1)
    p = es[0] // q0
    assert isPrime(p) and p.bit_length() == 1024, "p recovery failed"
    return p

def recover_mt_and_predict(qs, rs):
    # raw getrandbits output = randint_result - 2  (randint(2, 2**k))
    lin = LinearSystem([32] * 624); rng = MT19937(lin.gens()); zeros = []
    for qi, ri in zip(qs, rs):
        zeros.append(rng.getrandbits(1337) ^ (qi - 2))
        zeros.append(rng.getrandbits(200)  ^ (ri - 2))
    sol = lin.solve_one(zeros)
    assert sol is not None, "MT state under-determined; increase N"
    pr = MT19937(sol).to_python_random()
    for _ in range(len(qs)):                 # resync past the samples we consumed
        pr.getrandbits(1337); pr.getrandbits(200)
    q_next = pr.getrandbits(1337) + 2        # +2: randint(2, ...)
    r_next = pr.getrandbits(200)  + 2
    return q_next, r_next

def main():
    if len(sys.argv) >= 3:
        io = remote(sys.argv[1], int(sys.argv[2]))
    else:
        io = process(['python3', 'chal_local.py'])
    t0 = time.time()
    # ---- pipeline all N Put requests in one shot (minimise round trips) ----
    payload = b''.join(b'1\n%d\n0\n' % (i % 10) for i in range(N))
    io.send(payload)
    es = []
    while len(es) < N:
        line = io.recvline()
        m = re.search(rb'Successfully encrypted 0: (\d+)', line)
        if m: es.append(int(m.group(1)))
    log = time.time() - t0
    print(f"[*] collected {N} ciphertexts in {log:.2f}s")
    # ---- attack ----
    p = recover_p(es);                       print(f"[+] p recovered ({time.time()-t0:.2f}s)")
    qs = [e // p for e in es]; rs = [(e % p) // Q for e in es]
    q_next, r_next = recover_mt_and_predict(qs, rs)
    guess = p * q_next + Q * r_next + TARGET
    print(f"[+] guess computed ({time.time()-t0:.2f}s) -> submitting")
    # ---- claim the flag ----
    io.send(b'1337\n%d\n' % guess)
    print(f"[*] elapsed before submit: {time.time()-t0:.2f}s")
    data = io.recvall(timeout=5)
    print(data.decode(errors='replace'))

if __name__ == '__main__':
    main()