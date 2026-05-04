import base64

def solve_custom_base32():
    # 문제에서 주어진 암호문
    ciphertext = "IREHWYJZMEcGCODGMMbTENDDGcbGEMJZGEbGEZTFGYaGKNRTMIcGIMBSGRQTSNDDGAaWGYZRHEbGCNRQMUaDOMbEMRTGEYJYGUaWGOJQMYZHa==="
    
    # 힌트로 주어진 커스텀 알파벳 (총 32글자)
    custom_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
    
    # 파이썬 기본 base32 알파벳 (RFC 4648 표준)
    standard_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    
    print("[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] 원본 암호문 길이: {len(ciphertext)}자")
    print(f"[DEBUG] 커스텀 알파벳 ({len(custom_alphabet)}자): {custom_alphabet}")
    print(f"[DEBUG] 표준 알파벳 ({len(standard_alphabet)}자): {standard_alphabet}")
    print("[DEBUG] ========================================\n")
    
    # 변환 테이블 생성 및 문자열 치환
    translation_table = str.maketrans(custom_alphabet, standard_alphabet)
    standard_ciphertext = ciphertext.translate(translation_table)
    
    print("[DEBUG] === 문자 치환 상세 추적 (앞의 16글자 예시) ===")
    for i in range(16):
        orig = ciphertext[i]
        trans = standard_ciphertext[i]
        # 값이 바뀐 경우(소문자) 별도 표시
        changed = " (치환됨)" if orig != trans else ""
        print(f"[DEBUG] Index {i:03d}: '{orig}' -> '{trans}'{changed}")
    print("[DEBUG] ... (이하 중간 과정 출력 생략) ...\n")
    
    print("[DEBUG] === 치환 완료된 암호문 (표준 Base32 형태) ===")
    print(f"[DEBUG] {standard_ciphertext}\n")
    
    # 디코딩 시도
    try:
        print("[DEBUG] base64.b32decode() 함수로 디코딩을 시도합니다...")
        decoded_bytes = base64.b32decode(standard_ciphertext)
        flag = decoded_bytes.decode('utf-8')
        
        print(f"\n[DEBUG] ================= 결과 =================")
        print(f"[FLAG] {flag}")
        
    except Exception as e:
        print(f"[ERROR] 디코딩 중 에러가 발생했습니다: {e}")

if __name__ == "__main__":
    solve_custom_base32()