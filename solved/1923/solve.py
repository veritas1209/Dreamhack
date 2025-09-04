from cipher import STREAM

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def brute_force_seed(cipher_hex: str):
    cipher = bytes.fromhex(cipher_hex)
    known_plaintext = b'DH{'
    known_keystream = xor_bytes(cipher[:3], known_plaintext)

    for seed in range(0x100000000):  # 2^32 possibilities
        if seed % 1_000_000 == 0:
            print(f"Trying seed: {seed}")

        stream = STREAM(seed, 32)
        test_keystream = bytes([stream.bits2num(stream.getNbits(8)) for _ in range(3)])
        
        if test_keystream == known_keystream:
            print(f"[+] Found seed: {seed}")
            stream = STREAM(seed, 32)
            decrypted = stream.decrypt(cipher)
            print(f"[+] Decrypted flag: {decrypted.decode(errors='replace')}")
            return decrypted
    
    print("[-] Seed not found.")
    return None

if __name__ == "__main__":
    encrypted_flag = "c615a6cbc4bbf37fe65af240813248140925f2afb31f6c6b5bf71cdfa151fcd55999cf95e2eb9313fc75afe39d1bf836ef14931afe19e16a7c16a1bb41d5abe5d124991d"  # ← 실제 출력된 hex 문자열로 교체하세요
    brute_force_seed(encrypted_flag)
