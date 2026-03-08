from __future__ import annotations
import os
import struct
import time
from dataclasses import dataclass
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5

P = [101, 103, 107, 109, 113, 127, 131, 137]
Q = 0x1337C0FFEE

def _u64(x):
    return x & 0xFFFFFFFFFFFFFFFF
def pad16(b):
    n = 16 - (len(b) % 16)
    return b + bytes([n]) * n
@dataclass
class KM:
    k: bytes
    iv: bytes
class AESCipher:
    def __init__(self, t):
        self.t = int(t)
        self.km = self._km(self.t)
    @staticmethod
    def _seed(t: int):
        s = sum(P) * 0x1337
        x = _u64((t * 0xC0FFEE) ^ (s + Q))
        x ^= _u64((x << 13) | (x >> (64 - 13)))
        x = _u64(x + 0x9E3779B97F4A7C15)
        return x
    @classmethod
    def _km(cls, t):
        seed = cls._seed(t)
        h = SHA256.new()
        h.update(struct.pack("<Q", seed))
        h.update(b"3A91BC4F")
        k = h.digest()[:16]
        m = MD5.new()
        m.update(struct.pack("<Q", seed))
        m.update(k)
        iv = m.digest()
        return KM(k=k, iv=iv)
    def enc(self, pt):
        c = AES.new(self.km.k, AES.MODE_CBC, iv=self.km.iv)
        return c.encrypt(pad16(pt))
def main():
    in_path = "challenge"
    out_path = "challenge.enc"
    if not os.path.exists(in_path):
        return 1
    pt = open(in_path, "rb").read()
    t = int(time.time())
    aes = AESCipher(t)
    ct = aes.enc(pt)
    hdr = b"L0VE" + bytes([1]) + struct.pack("<Q", _u64(t) ^ 0xA5A5A5A5A5A5A5A5) + aes.km.iv
    with open(out_path, "wb") as f:
        f.write(hdr)
        f.write(ct)
    return 0

if __name__ == "__main__":
    main()