from Crypto.Util.number import GCD

import os
import hashlib

BITS = 1024

def getrandbits(bits):
    l = (bits + 7) // 8
    v = int.from_bytes(os.urandom(l), 'little')

    to_shift = 8 * l - bits
    return v >> to_shift

class LCG:
    def __init__(self, mod):
        self.mod = mod
        self.vs = [getrandbits(BITS // 3) for _ in range(6)]
        self.bs = [getrandbits(BITS) for _ in range(6)]
        self.c = getrandbits(BITS)
    
    def get(self):
        new_v = (sum(v * b for v, b in zip(self.vs, self.bs)) + self.c) % self.mod
        self.vs = self.vs[1:] + [new_v]
        return new_v


p = 0xd6911ad7da2912f38bd2d04c150be9b7fee1f5770e6a8ea7ffc0a559069b24ebfcd3d535b3ce2696f0b6ad7270bc76e023212bdaf6fa16da726098606dfc8d90246f4a94516a8fbd6290a96323b515995ecb66765fe1f66c39c928bf03ac1cbcbc8294aeed908e97d9d24f16f4ec88a98a4fd4ffa1c98d307521ba08a5b2a52b
assert p.bit_length() == BITS

a = int.from_bytes(os.urandom(BITS // 8), 'little')
lcg = LCG(p - 1)

vs = lcg.vs[:]

for i in range(20):
    print(pow(a, lcg.get(), p))

to_hash = "".join(str(v) for v in vs)
f = hashlib.sha256(to_hash.encode()).hexdigest()
flag = f"DH{{{f}}}"

with open('flag', 'w') as f:
    f.write(flag)

# If you have multiple flag candidates...
hashed_flag = hashlib.sha256(flag.encode()).hexdigest()
print(hashed_flag)