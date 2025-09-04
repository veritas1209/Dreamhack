import os
import random


def stream():
    i, j = 0, 0
    S = list(range(16))
    random.shuffle(S)

    while True:
        i = (i + 1) % 16
        j = (j + S[i]) % 16
        S[i], S[j] = S[j], S[i]

        yield S[i] ^ S[j]


with open("image.png", "rb") as f:
    data = f.read()

with open("image.png.enc", "wb") as f:
    for a, b in zip(data, stream()):
        f.write(bytes([a ^ b]))

os.remove("image.png")
