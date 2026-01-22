import struct

# 1. Target Vector B (From mem_trace.log)
# Q1은 로그상에서 LSB가 계속 변했으므로, 가장 자주 관측된 값(5c)을 쓰되
# Q2, Q3, Q4를 더 신뢰합니다.
B_hex = [
    0x584e55593354465c, # Q1 (불확실한 LSB: 5c)
    0x28d8b9338c6ef9a4, # Q2 (안정적)
    0x620c8634cddcccde, # Q3 (안정적)
    0xf1081a510d0dc22d  # Q4 (안정적)
]

print("[*] Starting Super Brute-force...")

def rol(val, n, width):
    return ((val << n) & ((1 << width) - 1)) | (val >> (width - n))

def ror(val, n, width):
    return ((val >> n) | (val << (width - n))) & ((1 << width) - 1)

def bits_to_bytes(val, width):
    try:
        return val.to_bytes(width // 8, 'little')
    except:
        return b""

def bits_to_bytes_be(val, width):
    try:
        return val.to_bytes(width // 8, 'big')
    except:
        return b""

# 다양한 데이터 해석 시도
candidates = []

# Case 1: 128-bit Chunks (Little Endian)
# Chunk1 = Q2:Q1, Chunk2 = Q4:Q3
c1_128_le = (B_hex[1] << 64) | B_hex[0]
c2_128_le = (B_hex[3] << 64) | B_hex[2]
candidates.append(("128-bit LE", c1_128_le, 128))

# Case 2: 128-bit Chunks (Big Endian logic with LE words)
# Chunk1 = Q1:Q2 ??
c1_128_be = (B_hex[0] << 64) | B_hex[1]
candidates.append(("128-bit BE", c1_128_be, 128))

# Case 3: Full 256-bit
full_256 = (B_hex[3] << 192) | (B_hex[2] << 128) | (B_hex[1] << 64) | B_hex[0]
candidates.append(("256-bit LE", full_256, 256))

# 공격 실행
found = False
for desc, val, width in candidates:
    # 0 ~ width 비트만큼 회전 시도
    for k in range(width):
        # Left Rotate & Right Rotate 모두 시도
        for func_name, func in [("ROL", rol), ("ROR", ror)]:
            res = func(val, k, width)
            
            # 바이트 변환 (Little & Big Endian 모두 확인)
            b_le = bits_to_bytes(res, width)
            b_be = bits_to_bytes_be(res, width)
            
            for b_data, endian in [(b_le, "LE"), (b_be, "BE")]:
                # 플래그 패턴 검색 ("DH{" 또는 "flag{")
                if b"DH{" in b_data or b"flag{" in b_data:
                    print("\n" + "="*60)
                    print(f"[!] FLAG FOUND in {desc} ({endian}) via {func_name}({k})")
                    print("-" * 60)
                    print(f"Hex: {b_data.hex()}")
                    try:
                        print(f"String: {b_data.decode('utf-8', errors='ignore')}")
                    except:
                        pass
                    print("="*60)
                    found = True

if not found:
    print("[!] Pattern not found. Checking if Q1 LSB (0x5c) is noise...")
    # Q1의 첫 바이트가 깨져서 "DH{" 매칭이 안 될 수도 있음.
    # "H{" (48 7B) 패턴으로 재검색
    for desc, val, width in candidates:
        for k in range(width):
            res = ror(val, k, width)
            b_data = bits_to_bytes(res, width)
            if b"H{" in b_data or b"lag{" in b_data:
                 print(f"[?] Potential Match (Partial): {b_data}")