from hashlib import sha256, shake_256

FLAG = b"DH{This_is_fake_flag}"

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def long_to_bytes(n):
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

moduli = [2147483659, 2147483693, 2147483713, 2147483743, 2147483777, 2147483817]
secret = int.from_bytes(sha256(b"lee-remainder-easy-key").digest()[:16], "big")
remainders = [secret % m for m in moduli]
nonce = bytes.fromhex("1337133713371337")
ciphertext = xor_bytes(FLAG, shake_256(long_to_bytes(secret) + nonce).digest(len(FLAG)))

print(f"moduli = {moduli}")
print(f"remainders = {remainders}")
print(f"nonce = {nonce.hex()}")
print(f"ciphertext = {ciphertext.hex()}")