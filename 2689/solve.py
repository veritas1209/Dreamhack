import struct

def decrypt_decoy():
    # 1. Ciphertext (From check function: 0x1e5cc8f90ebd34d5)
    # Little Endian 메모리 구조: D5 34 BD 0E F9 C8 5C 1E
    # v0 = 0x0ebd34d5, v1 = 0x1e5cc8f9
    v0 = 0x0ebd34d5
    v1 = 0x1e5cc8f9

    # 2. Keys (From encrypt function)
    # 0: 0x2bf41bd5
    # 1: -0x7ce56ba9 -> 0x831a9457
    # 2: -0xe9846ff  -> 0xf167b901
    # 3: -0x4e8230a1 -> 0xb17dcf5f
    k = [0x2bf41bd5, 0x831a9457, 0xf167b901, 0xb17dcf5f]

    # 3. Constants
    delta = 0x9e3779b9
    limit = 0x20 # 32 rounds
    sum_val = (delta * limit) & 0xffffffff # Decrypt는 sum을 거꾸로 시작

    print(f"[*] Decrypting Decoy Cipher: {hex(v0)} {hex(v1)}")

    # 4. Decryption Loop (Reverse of encrypt)
    for _ in range(limit):
        # --- Reverse v1 calculation ---
        # Original: local_28 += (key + sum ^ (v0<<4 ^ v0>>5) + v0)
        # Check sum bits for Key Selection (v1 part uses 0x1800 mask)
        
        idx = 0
        if (sum_val & 0x1800) == 0:      idx = 0
        elif (sum_val & 0x1800) == 0x800: idx = 1
        elif (sum_val & 0x1800) == 0x1000: idx = 2
        else:                            idx = 3
        
        key_val = k[idx]
        term = (key_val + sum_val) ^ (((v0 << 4) & 0xffffffff ^ (v0 >> 5)) + v0)
        v1 = (v1 - term) & 0xffffffff

        # --- Reverse v0 calculation ---
        # Original: local_2c += (key + sum ^ (v1<<4 ^ v1>>5) + v1)
        # Check sum bits for Key Selection (v0 part uses & 3 mask) -> No!
        # Wait, look at the C code carefully.
        # It updates local_2c (v0), THEN updates local_24 (sum), THEN updates local_28 (v1).
        
        # So in reverse: 
        # 1. Reverse v1 update (done above)
        # 2. Reverse sum update (sum -= delta)
        # 3. Reverse v0 update

        sum_val = (sum_val - delta) & 0xffffffff

        idx = 0
        if (sum_val & 3) == 0: idx = 0
        elif (sum_val & 3) == 1: idx = 1
        elif (sum_val & 3) == 2: idx = 2
        else: idx = 3

        key_val = k[idx]
        term = (key_val + sum_val) ^ (((v1 << 4) & 0xffffffff ^ (v1 >> 5)) + v1)
        v0 = (v0 - term) & 0xffffffff

    # 5. Result
    res = struct.pack('<II', v0, v1)
    print(f"[*] Result (Hex): {res.hex()}")
    print(f"[*] Result (Str): {res}")

if __name__ == "__main__":
    decrypt_decoy()