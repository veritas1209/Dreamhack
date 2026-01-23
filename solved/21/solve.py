def ror(val, n):
    """
    8-bit Rotate Right (오른쪽 회전)
    Original Code의 Left Rotate를 역연산하기 위함
    """
    return ((val >> n) | (val << (8 - n))) & 0xFF

# Ghidra 데이터 섹션에서 추출한 암호화된 바이트 배열 (0x00 ~ 0x1E)
enc_bytes = [
    0x52, 0xdf, 0xb3, 0x60, 0xf1, 0x8b, 0x1c, 0xb5,
    0x57, 0xd1, 0x9f, 0x38, 0x4b, 0x29, 0xd9, 0x26,
    0x7f, 0xc9, 0xa3, 0xe9, 0x53, 0x18, 0x4f, 0xb8,
    0x6a, 0xcb, 0x87, 0x58, 0x5b, 0x39, 0x1e
]

flag = ""

print(f"[*] Decrypting {len(enc_bytes)} bytes...")

for i in range(len(enc_bytes)):
    # 1. XOR 역연산: (Encrypted ^ Index)
    # 원본 코드: (Rotated ^ i) == Target
    xor_val = enc_bytes[i] ^ i
    
    # 2. Shift 양 계산: (Index % 8)
    shift = i & 7
    
    # 3. Rotate Left의 역연산 -> Rotate Right 수행
    decrypted_char = ror(xor_val, shift)
    
    # 4. 결과 문자열에 추가
    flag += chr(decrypted_char)

print(f"\n[+] Flag Found: {flag}")