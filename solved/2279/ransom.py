import hashlib
import random

k = b"DH{cry_m3_4_r1v3r_0x??????}" 

def a(data: bytes, uk: bytes) -> bytes:
    seed = int.from_bytes(hashlib.md5(uk).digest(), 'big')
    random.seed(seed)
    indices = list(range(len(data)))
    random.shuffle(indices)
    return bytes([data[i] for i in indices])

def b(data: bytes, k: bytes) -> bytes:
    k_stream = hashlib.sha256(k).digest()
    return bytes([b ^ k_stream[i % len(k_stream)] for i, b in enumerate(data)])

def c(data: bytes, k: bytes) -> bytes:
    uk = b"cry_me_a_river"
    ad = a(data, uk)
    y = b(ad, k)
    return y

plain = f.read()
lol = c(plain, k)
