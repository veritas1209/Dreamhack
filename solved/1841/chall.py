import os
a = int.from_bytes(os.urandom(2), byteorder="little")
b = int.from_bytes(os.urandom(2), byteorder="little")
mod = 65521    # prime number!!
seed = int.from_bytes(os.urandom(2), byteorder="little") % mod

def rand():
    global a, b, mod, seed
    seed = (a * seed + b) % mod
    return seed

plain = open("flag.bmp", "rb")
encrypted = open("flag.bmp.enc", "wb")
while True:
    p = plain.read(2)
    if p == b"":
        break
    encrypted.write((int.from_bytes(p, byteorder="little") ^ rand()).to_bytes(2, byteorder="little", signed=False))
encrypted.close()