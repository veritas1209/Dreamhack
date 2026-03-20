import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secret import *

r = random.Random(key_of_song) # The key should be a letter
nums = [r.getrandbits(32) for _ in range(tempo)]

p = 1

for i in nums:
    p *= i

key = sha256((str(secret) + str(p)).encode()).digest()[:16]

cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(flag, 16))

print(ct.hex()) # f0509319eab2fd63d05ad829b9e8ade42624ac30a2841ee1f130db7ad050a6b5943d959ba5fce6e169950505f310f105ba0b44ada8d8da605f20e97256e2db24