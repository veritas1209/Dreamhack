from pwn import *
from fractions import Fraction
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
E = 0x10001

def solve_once(io):
    io.sendlineafter(b"p_lsb > ", b"1")
    io.sendlineafter(b"q_lsb > ", b"1")
    io.recvuntil(b"n: ")
    n = int(io.recvline().strip())
    io.recvuntil(b"enc(target): ")
    enc = int(io.recvline().strip())

    # need n's bit#128 == 0 for the clean LSB reduction
    if (n >> 128) & 1 != 0:
        log.info("n bit#128 = 1, reconnecting...")
        return False

    two128 = pow(2, 128, n)

    def oracle_bit128(k):
        # bit#128 of (k*target mod n)
        c = (pow(k, E, n) * enc) % n
        io.sendlineafter(b"c > ", str(c).encode())
        line = io.recvline()
        # line like b"o: 0\n"; defensively scan
        while b"o:" not in line:
            line = io.recvline()
        return int(line.split(b"o:")[1].strip())

    def lsb(k):
        # bit0 of (k*target mod n)
        return oracle_bit128((k * two128) % n) ^ 1

    # sanity self-check on a couple of values is impossible without target; trust derivation.
    lo = Fraction(0)
    hi = Fraction(n)
    nbits = n.bit_length()
    for i in range(1, nbits + 1):
        b = lsb(pow(2, i, n))           # parity of (2^i * target mod n)
        mid = (lo + hi) / 2
        if b == 0:
            hi = mid
        else:
            lo = mid

    cand = int(hi)
    target = None
    for t in range(cand - 3, cand + 4):
        if 0 <= t < n and pow(t, E, n) == enc:
            target = t
            break
    if target is None:
        log.warning("recovery failed, reconnecting")
        return False

    log.success(f"recovered target = {target}")
    # send c == target to win
    io.sendlineafter(b"c > ", str(target).encode())
    data = io.recvall(timeout=5)
    print(data.decode(errors="replace"))
    return True

def main():
    while True:
        io = remote(HOST, PORT)
        try:
            if solve_once(io):
                break
        except EOFError:
            pass
        finally:
            io.close()

if __name__ == "__main__":
    main()