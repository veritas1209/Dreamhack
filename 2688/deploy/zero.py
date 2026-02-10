# make_zero.py
with open("zero_input", "wb") as f:
    f.write(b'\x00' * 64)
print("[+] zero_input created.")