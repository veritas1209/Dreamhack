import struct

# --- 1. Custom XTEA Decrypt ---
def decrypt_xtea_custom(v, k):
    # v: [v0, v1] (uint32)
    # k: [k0, k1, k2, k3] (uint32)
    v0, v1 = v[0], v[1]
    
    delta = 0x9e3779b9
    # 암호화 루프가 32번 돌고 난 후의 sum 값
    sum_val = (delta * 32) & 0xFFFFFFFF
    
    for _ in range(32):
        # [Step 1] Reverse v1 update
        # 암호화 시점: sum이 이미 업데이트된 상태에서 v1을 계산함.
        # 따라서 복호화 시점의 현재 sum을 그대로 사용하여 키를 선택.
        
        # Key Select (bit 11, 12) => (sum >> 11) & 3
        # if (sum & 0x1800) ...
        mask = sum_val & 0x1800
        if mask == 0: key_v1 = k[0]
        elif mask == 0x800: key_v1 = k[1]
        elif mask == 0x1000: key_v1 = k[2]
        else: key_v1 = k[3]
            
        term2 = (key_v1 + sum_val) & 0xFFFFFFFF
        term1 = ((v0 << 4) ^ (v0 >> 5)) + v0
        term1 &= 0xFFFFFFFF
        
        v1 = (v1 - (term2 ^ term1)) & 0xFFFFFFFF
        
        # [Step 2] Reverse sum update
        sum_val = (sum_val - delta) & 0xFFFFFFFF
        
        # [Step 3] Reverse v0 update
        # 암호화 시점: sum 업데이트 전의 값을 사용했음.
        # 방금 sum을 복구했으므로, 현재 sum이 바로 그 '업데이트 전' 값임.
        
        mask = sum_val & 3
        if mask == 0: key_v0 = k[0]
        elif mask == 1: key_v0 = k[1]
        elif mask == 2: key_v0 = k[2]
        else: key_v0 = k[3]
            
        term2 = (key_v0 + sum_val) & 0xFFFFFFFF
        term1 = ((v1 << 4) ^ (v1 >> 5)) + v1
        term1 &= 0xFFFFFFFF
        
        v0 = (v0 - (term2 ^ term1)) & 0xFFFFFFFF
        
    return [v0, v1]

# --- 2. Base-255 Decoding ---
def decode_base255(block_8bytes):
    # main함수 인코딩 로직 역산:
    # 7바이트 숫자 -> 8바이트 Base-255 문자열
    # 메모리에 쓰일 때 역순으로 쓰임 (puVar15--)
    # 따라서 block_8bytes[0]이 가장 높은 자릿수(MSB)일 가능성 큼.
    
    val = 0
    # Big Endian 처럼 앞에서부터 처리
    for b in block_8bytes:
        # 인코딩 식: byte = digit + 1
        digit = b - 1
        if digit < 0: digit = 0 # Should not happen
        
        val = val * 255 + digit

    # 56-bit Integer 'val'을 7바이트로 변환
    # main에서 uVar7 << 8 | bVar12 로 모았으므로 Big Endian.
    
    decoded = bytearray(7)
    for i in range(6, -1, -1):
        decoded[i] = val & 0xFF
        val //= 256
        
    return bytes(decoded)

# --- 3. Verification ---
def verify():
    print("[*] Verifying bin_0 Logic...")
    
    # Target: 0x1e5cc8f90ebd34d5
    # Memory Layout (Little Endian): D5 34 BD 0E F9 C8 5C 1E
    # v0 (Lower 4 bytes) = 0x0ebd34d5
    # v1 (Upper 4 bytes) = 0x1e5cc8f9
    target = [0x0ebd34d5, 0x1e5cc8f9]
    
    # Keys
    keys = [
        0x2bf41bd5,
        (-0x7ce56ba9) & 0xFFFFFFFF, # 0x831a9457
        (-0xe9846ff) & 0xFFFFFFFF,  # 0xf167b901
        (-0x4e8230a1) & 0xFFFFFFFF  # 0xb17dcf5f
    ]
    
    print(f"[*] Decrypting XTEA...")
    dec = decrypt_xtea_custom(target, keys)
    print(f"    -> Raw v0: {hex(dec[0])}, v1: {hex(dec[1])}")
    
    # Pack to 8 bytes (Little Endian Memory Layout)
    # v0가 먼저(하위 주소), v1이 나중(상위 주소)
    enc_bytes = struct.pack('<II', dec[0], dec[1])
    print(f"    -> Encoded Bytes (Hex): {enc_bytes.hex()}")
    
    print(f"[*] Decoding Base-255...")
    png_chunk = decode_base255(enc_bytes)
    print(f"    -> Decoded Chunk (Hex): {png_chunk.hex().upper()}")
    
    # Check against PNG Header (First 7 bytes)
    # 89 50 4E 47 0D 0A 1A
    expected = b'\x89\x50\x4E\x47\x0D\x0A\x1A'
    
    if png_chunk == expected:
        print("\n[!!!] SUCCESS! Logic verified perfectly.")
        print("[+] This logic can now be applied to all bins.")
    else:
        print(f"\n[-] FAILED. Expected {expected.hex().upper()}, got {png_chunk.hex().upper()}")

verify()