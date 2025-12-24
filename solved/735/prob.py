import random
from Crypto.Util.number import isPrime, bytes_to_long, inverse, long_to_bytes
from secret import flag
from math import gcd    


class KNAP_SACK():
    def __init__(self, size):
        s = 1225
        b = []
        for _ in range(size):
            ai = random.randint(s + 1, 2 * s)
            assert ai > sum(b)
            b.append(ai)
            s += ai
            
        while True:
            q = random.randint(2 * s, 32 * s)
            if isPrime(q):
                break
            
        r = random.randint(s, q)
        
        assert q > sum(b)
        assert gcd(q,r) == 1
        
        self.b = b
        self.r = r
        self.q = q
        
        self.a = []
        for x in self.b:
            self.a.append((self.r * x) % self.q)
    
    def get_private_key(self):
        return (self.b, self.r, self.q)
    
    def get_public_key(self):
        return self.a
    
    def encrypt(self, M):
        assert len(M) * 8 <= len(self.a)
        ct = 0
        M = bytes_to_long(M)
        for bi in self.a:
            ct += (M & 1) * bi
            M >>= 1
        return ct


encryptor = KNAP_SACK(len(flag) * 8)
enc = encryptor.encrypt(flag)
print(f"pub = {encryptor.get_public_key()}")
print(f'enc = {enc}')
