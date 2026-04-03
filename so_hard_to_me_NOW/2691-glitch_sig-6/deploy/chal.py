from Crypto.Util.number import getPrime, GCD
from collections import namedtuple
import random
import signal

TIMEOUT = 30

rand = random.SystemRandom()
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


def sign(msg, priv, bits=64, is_faulty=False):
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


def verify(msg, sig, pub):
    return pow(sig, pub.e, pub.N) == msg


def main():
    pub, priv = keygen()

    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(TIMEOUT)
    
    msg = rand.getrandbits(500)
    assert verify(msg, sign(msg, priv), pub)

    for _ in range(20):
        faulty_sig = sign(msg, priv, is_faulty=True)
        print(f"{faulty_sig = }")
    
    if int(input("> ").strip()) == msg:
        with open("flag", "rb") as f:
            print(f"Flag is: {f.read()}")


if __name__ == "__main__":
    main()