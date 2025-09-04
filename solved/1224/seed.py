# DREAMHACK CHALLENGE - INSECURE SEED #

import os
import random
from typing import List

class Seed:
    def __init__ (self) -> None:
        self.a: int = os.urandom(1)

    @staticmethod
    def GenerateSeed() -> List[int]:
        seed: bytearray = bytearray(random.getrandbits(8) for x in range(4))
        return list(seed)
        
    def CalculateKey(self, seed: List[int]) -> bool:
        key: List[int] = [0] * len(seed)
        
        for i in range(len(seed)):
            result: bytes = bytes([self.a[j] ^ seed[i] for j in range(len(self.a))])
            key[i] = int.from_bytes(result, byteorder='little')
        return key
    
    def Authentication(self, seed: List[int], k: List[int]) -> bool:
        key = self.CalculateKey(seed)
        
        if key == k:
            print('Correct!!')
            return True
        else:
            print('Invalid Key!!')
            return False

if __name__ == "__main__":
    s = Seed()
    
    seed = s.GenerateSeed()
    print(f"Seed: {seed}")
    
    while 1:
        k = input("Key: ").strip().split() # input ex) 41 42 43 44
        kl = [int(x) for x in k]
        
        if s.Authentication(seed, kl):
            break
    
    print('DH{fake_flag}')