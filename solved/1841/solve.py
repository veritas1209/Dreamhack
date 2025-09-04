

# 구한 키를 여기에 넣으세요.
a = 52661
b = 23300
mod = 65521
seed = 2334

def rand():
    global a, b, mod, seed
    seed = (a * seed + b) % mod
    return seed

encrypted = open(r"C:\Users\김하진\해킹스터디\dreamhack\1841\flag.bmp.enc", "rb")
decrypted = open(r"C:\Users\김하진\해킹스터디\dreamhack\1841\flag.bmp", "wb")
while True:
    p = encrypted.read(2)
    if p == b"":
        break
    decrypted.write((int.from_bytes(p, byteorder="little") ^ rand()).to_bytes(2, byteorder="little", signed=False))
decrypted.close()
