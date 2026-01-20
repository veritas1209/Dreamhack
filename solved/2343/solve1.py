import hashlib

with open("answer.bin", "rb") as f:
    data = f.read()
    flag_hash = hashlib.sha256(data).hexdigest()
    print(f"DH{{{flag_hash}}}")