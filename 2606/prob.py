from cipher import Cipher
import random

engine = random.SystemRandom()
key = engine.sample(range(256), 256)
nonce = engine.randrange(2 ** 32)
c = Cipher(key, nonce)

a = open("flag.bmp", "rb").read()
b = open("flag.bmp.enc", "wb")
b.write(c.encrypt(a))
b.close()