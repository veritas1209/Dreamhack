from Crypto.Util.number import getPrime, GCD
from collections import namedtuple
import hashlib
import random
import signal

rand = random.SystemRandom()
TIMEOUT = 10

Pubkey = namedtuple("Pubkey", ["N", "e"])
Privkey = namedtuple("Privkey", ["p", "q", "dp", "dq", "qinv"])


def timeout(signum, frame):
    print("TIMEOUT!!!")
    exit(0)


def keygen(bits=256):
    while True:
        p = getPrime(bits)
        q = getPrime(bits)
        e = 65537
        phi = (p - 1) * (q - 1)

        if GCD(phi, e) == 1:
            break
    
    N = p * q
    d = pow(e, -1, phi)
    dp, dq = d % (p - 1), d % (q - 1)
    qinv = pow(q, -1, p)

    return Pubkey(N, e), Privkey(p, q, dp, dq, qinv)


def hash_msg(msg: bytes) -> int:
    res = hashlib.sha256(msg + rand.randbytes(8)).digest()
    
    return int.from_bytes(msg + res[:6], "big")


def sign(msg, priv, bits=256, is_faulty=False):
    msg = hash_msg(msg)
    msg_p, msg_q = msg % priv.p, msg % priv.q
    if is_faulty:
        dp = priv.dp ^ (1 << rand.randint(0, bits - 1))
    else:
        dp = priv.dp

    s_p = pow(msg_p, dp, priv.p)
    s_q = pow(msg_q, priv.dq, priv.q)
    t = (s_p - s_q) % priv.p
    s = s_q + (t * priv.qinv % priv.p) * priv.q
    return s


def main():
    pub, priv = keygen()

    print(f"{pub = }")

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(TIMEOUT)

    for _ in range(10):
        msg = bytes.fromhex(input("> ").strip())
        faulty_sig = sign(msg, priv, is_faulty=True)
        print(f"{faulty_sig = }")
    
    if int(input("> ").strip()) in [priv.p, priv.q]:
        with open("flag", "rb") as f:
            print(f"Flag is: {f.read()}")


if __name__ == "__main__":
    main()