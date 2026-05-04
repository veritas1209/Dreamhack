import os

def solve_ctf_recover(encrypted_filepath, output_filepath):
    # 바이너리에서 추출한 4바이트 키 배열 (0xde, 0xad, 0xbe, 0xef)
    key = [0xde, 0xad, 0xbe, 0xef]
    
    print(f"[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] 입력 파일(암호화됨): {encrypted_filepath}")
    print(f"[DEBUG] 출력 파일(복호화됨): {output_filepath}")
    print(f"[DEBUG] 복호화 키 배열: {[hex(k) for k in key]}")
    print(f"[DEBUG] ========================================\n")
    
    if not os.path.exists(encrypted_filepath):
        print(f"[ERROR] '{encrypted_filepath}' 파일이 현재 디렉토리에 없습니다.")
        return

    try:
        with open(encrypted_filepath, 'rb') as f_in, open(output_filepath, 'wb') as f_out:
            encrypted_data = f_in.read()
            total_bytes = len(encrypted_data)
            print(f"[DEBUG] '{encrypted_filepath}' 읽기 완료. (총 {total_bytes} bytes)\n")
            
            decrypted_data = bytearray()
            
            for i, c in enumerate(encrypted_data):
                # 1단계: 0x13 빼기 (8비트 언더플로우 방지를 위해 & 0xFF 처리)
                step1 = (c - 0x13) & 0xFF
                
                # 2단계: XOR 연산으로 원본 바이트 복구
                current_key = key[i % 4]
                p = step1 ^ current_key
                
                decrypted_data.append(p)
                
                # 너무 많은 출력이 발생하여 콘솔이 멈추는 것을 방지하기 위해
                # 처음 16바이트와 마지막 16바이트의 상세 과정만 출력합니다.
                # (모든 바이트의 디버깅이 필요하다면 아래 if 조건문을 지워주세요.)
                if i < 16 or i >= total_bytes - 16:
                    # PNG 헤더나 텍스트를 확인하기 위해 출력 가능 문자는 문자로 같이 표기
                    char_repr = chr(p) if 32 <= p <= 126 else '.'
                    print(f"[DEBUG] Offset: {i:04x} | Encrypted: {c:02X} | -0x13: {step1:02X} | XOR Key({i%4}): {current_key:02X} | Decrypted: {p:02X} ('{char_repr}')")
                elif i == 16:
                    print(f"[DEBUG] ... (중간 데이터 {total_bytes - 32} 바이트 처리 생략) ...")
            
            f_out.write(decrypted_data)
            print(f"\n[DEBUG] ================= 결과 =================")
            print(f"[DEBUG] 복호화가 완료되어 '{output_filepath}'에 성공적으로 저장되었습니다.")
            
    except Exception as e:
        print(f"[ERROR] 파일 처리 중 오류가 발생했습니다: {e}")

if __name__ == "__main__":
    # 스크립트와 같은 폴더에 'encrypted' 파일이 있어야 합니다.
    solve_ctf_recover("encrypted", "flag.png")