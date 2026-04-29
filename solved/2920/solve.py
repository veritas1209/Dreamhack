def ror3(val):
    # ROL 3의 역연산인 ROR 3 (오른쪽으로 3비트 회전)
    return ((val >> 3) | (val << 5)) & 0xFF

def decode_flag():
    print("==================================================")
    print("[*] [DEBUG] CTF Flag 수학적 역연산 최종 스크립트 실행")
    print("==================================================")
    
    # 기드라 & GDB에서 교차 검증된 타겟 배열
    target_bytes = [
        0x90, 0xE6, 0xBE, 0x92, 0xAE, 0xD6, 0xBB, 0x9F,
        0xBE, 0xD4, 0x64, 0xED, 0x1F, 0x3F, 0x75, 0x39,
        0x76, 0x74, 0x8C, 0x15, 0xC9, 0x48, 0x9D, 0xC9,
        0xA6, 0x6C, 0x1C, 0x4E
    ]
    
    # GDB에서 검증된 XOR 키 배열
    xor_key = [0x99, 0x4B, 0x8D, 0x47, 0x7B, 0x30, 0x6F, 0x68]
    arr = list(target_bytes)
    
    print("\n[*] [DEBUG] 1단계: 역방향 덧셈 복호화 (뺄셈)")
    for i in range(len(arr) - 1):
        original_val = arr[i]
        arr[i] = (arr[i] - arr[i+1]) % 256
        print(f"    [Trace] Index {i:02d}: {hex(original_val)} - {hex(arr[i+1])} = {hex(arr[i])}")
        
    print("\n[*] [DEBUG] 2단계 & 3단계: XOR 복호화 및 ROR 3 (비트 우측 회전) 수행")
    flag_inner = ""
    for i in range(len(arr)):
        # 2단계: XOR 키 역연산
        xored_val = arr[i] ^ xor_key[i % 8]
        
        # 3단계: ROR 3 역연산으로 평문 복구
        restored_char_val = ror3(xored_val)
        char = chr(restored_char_val)
        flag_inner += char
        
        print(f"    [Trace] Index {i:02d}: XOR({hex(arr[i])}, {hex(xor_key[i%8])}) = {hex(xored_val)} -> ROR3 = {hex(restored_char_val)} ('{char}')")
        
    print("\n==================================================")
    print(f"[*] [RESULT] 🚩 획득한 최종 플래그: DH{{{flag_inner}}}")
    print("==================================================")

if __name__ == "__main__":
    decode_flag()