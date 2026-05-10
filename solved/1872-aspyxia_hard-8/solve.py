import sys

def decode_stage2(hex_string):
    print("[*] --- Stage 2 (DAT_00104020) 복호화 프로세스 시작 ---")
    try:
        packed_data = bytes.fromhex(hex_string.replace(" ", "").replace("\n", ""))
    except ValueError:
        print("[!] 헥스 스트링 형식이 올바르지 않습니다.")
        return

    print(f"[*] 원본 데이터 길이: {len(packed_data)} bytes")
    
    decoded_out = bytearray()
    local_1c = 0x1f
    idx = 0
    
    while idx < len(packed_data):
        # Null 바이트 건너뛰기
        while idx < len(packed_data) and packed_data[idx] == 0:
            idx += 1
            
        if idx >= len(packed_data): 
            break
            
        cVar2 = packed_data[idx]
        
        # 종료 조건
        if cVar2 < 0x24:
            print(f"\n[*] 종료 조건 충족! (0x{cVar2:02x} < 0x24). 복호화 루프 탈출.")
            break
            
        idx += 1
        while idx < len(packed_data) and packed_data[idx] == 0:
            idx += 1
            
        if idx >= len(packed_data): 
            break
            
        next_char = packed_data[idx]
        
        # 연산 코어
        old_local_1c = local_1c
        local_1c = (local_1c * 0x2000 + next_char * 0x5b + cVar2) - 0xcf0
        print(f"[=] 상태 업데이트: 0x{old_local_1c:x} -> 0x{local_1c:x} (cVar2: 0x{cVar2:02x}, next: 0x{next_char:02x})")
        
        # 바이트 추출
        while True:
            extracted_byte = local_1c & 0xFF
            decoded_out.append(extracted_byte)
            print(f"    [-] 추출: 0x{extracted_byte:02x} | 남은 상태: 0x{(local_1c >> 8):x}")
            local_1c = local_1c >> 8
            
            if (local_1c & 0x1000) == 0:
                break
                
        idx += 1

    print("\n[*] --- 복호화 완료 ---")
    print(f"[*] 최종 복호화 길이: {len(decoded_out)} bytes")
    
    with open("stage2_payload.bin", "wb") as f:
        f.write(decoded_out)
    print("[*] stage2_payload.bin 파일로 성공적으로 저장했습니다!")

if __name__ == "__main__":
    # TODO: Ghidra에서 DAT_00104020 영역의 헥스값을 통째로 복사해서 아래 변수에 넣어주세요.
    # 예시: dat_00104020_hex = "48 3b 7c ..."
    dat_00104020_hex = "" 
    
    if dat_00104020_hex:
        decode_stage2(dat_00104020_hex)
    else:
        print("[!] 스크립트 하단의 dat_00104020_hex 변수에 Ghidra에서 추출한 헥스값을 채워주세요.")

        