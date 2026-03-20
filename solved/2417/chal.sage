from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import os

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
E = EllipticCurve(GF(p), [-3, b])
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
assert n * G == E(0)

Fp = GF(p)
Fn = GF(n)

PRn.<xn> = PolynomialRing(Fn)
class PRNG:
    def __init__(self):
        self.state = os.urandom(32)

    def next(self):
        while True:
            self.state = sha256(self.state).digest()
            f = xn^71 - bytes_to_long(self.state)
            l = list(factor(f))
            if len(l) == 71:
                break
        root = -l[0][0][0]
        assert root^71 == bytes_to_long(self.state)
        return ZZ(root)

FLAG = 'KoS{[REDACTED]}'
key = os.urandom(32)
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted_flag = cipher.encrypt(pad(FLAG.encode(), 16))

priv = bytes_to_long(key)
pub = priv * G
prng = PRNG()

def sign(priv, message, k):
    kG = k * G
    r = ZZ(kG[0])
    h = bytes_to_long(sha256(message).digest())
    s = (h + r * priv) / k % n
    return r, s

def verify(pub, message, r, s):
    h = bytes_to_long(sha256(message).digest())
    u1 = h/s % n
    u2 = r/s % n
    kG = u1 * G + u2 * pub
    assert kG[0] == r

X = FLAG.encode()
with open("miyako.txt", "r") as f:
    lines = [line.encode() for line in f.read().split('\n') if line]
    for i, line in enumerate(lines):
        X = sha256(X).digest()
        cipher = AES.new(X, AES.MODE_CBC, iv)
        lines[i] = cipher.encrypt(pad(line, 16))

signs = []
for line in lines:
    k = prng.next()
    r, s = sign(priv, line, k)
    verify(pub, line, r, s)
    signs.append((r, s, line.hex()))

with open("output.sage", "w") as f:
    f.write(f"pub = {pub.xy()}\n")
    f.write(f"signs = {signs}\n")
    f.write(f"encrypted_flag = '{encrypted_flag.hex()}'\n")
    f.write(f"iv = '{iv.hex()}'\n")