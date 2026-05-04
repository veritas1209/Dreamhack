def solve_legacyopt():
    # 문제에서 주어진 암호화된 헥스 스트링
    encrypted_hex = "220c6a33204455fb390074013c4156d704316528205156d70b217c14255b6ce10837651234464e"
    encrypted_data = bytes.fromhex(encrypted_hex)
    length = len(encrypted_data)
    
    # 디컴파일된 코드의 case 0 ~ case 1 순서대로 나열한 XOR 키 배열
    # (코드 흐름상 위에서 아래로 순차적으로 실행됨)
    keys = [0x88, 0x66, 0x44, 0x11, 0x77, 0x55, 0x22, 0x33]
    
    # Duff's Device 특성상, 길이의 나머지 값에 따라 시작하는 키의 위치가 달라집니다.
    # L % 8 == 7 이면, case 7 (0x66)부터 시작 (인덱스 1)
    start_offset = (8 - (length % 8)) % 8
    
    print(f"[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] Encrypted Hex : {encrypted_hex}")
    print(f"[DEBUG] Data Length   : {length} bytes")
    print(f"[DEBUG] Length % 8    : {length % 8}")
    print(f"[DEBUG] Key Array     : {[hex(k) for k in keys]}")
    print(f"[DEBUG] Start Offset  : {start_offset} (Starts with {hex(keys[start_offset])})")
    print(f"[DEBUG] ========================================\n")
    
    decrypted_chars = []
    
    # 각 바이트별 디버깅 추적
    for i in range(length):
        enc_byte = encrypted_data[i]
        
        # 현재 바이트에 적용될 키 인덱스 계산 (8주기로 순환)
        key_index = (start_offset + i) % 8
        current_key = keys[key_index]
        
        # XOR 역연산 수행
        dec_byte = enc_byte ^ current_key
        dec_char = chr(dec_byte)
        decrypted_chars.append(dec_char)
        
        # 가독성을 위해 출력 불가능한 제어 문자는 점(.)으로 표시, 나머지는 그대로 출력
        safe_char = dec_char if 32 <= dec_byte <= 126 else '.'
        
        print(f"[DEBUG] Index: {i:02d} | Enc: 0x{enc_byte:02X} | Key({key_index}): 0x{current_key:02X} | Dec: 0x{dec_byte:02X} ('{safe_char}')")
        
    flag = "".join(decrypted_chars)
    print(f"\n[DEBUG] ================= 결과 =================")
    print(f"[FLAG] {flag}")

if __name__ == "__main__":
    solve_legacyopt()