import base64

# 주어진 데이터
text_in = "Pepero is a cookie stick, dipped in compound chocolate, manufactured by ????? Confectionery in South Korea\nPepero Day is held annually on November 11"
text_out = "7/OkZQIau/jou/R1by9acyjjutd0cUdlWshecQhkZUn1cUH1by9g4/9qNAn1byGaby9pbQSjWshgbUmqZAF+JtOBZUn1b8e1YoMPYoM1ny95ZAO+J/jaNAOB2vhrNLhVNDO0cshWNDIjbnrnZQhj4AM1S/Fmu/jou/GjN/n1bUm5JUFpNte1NyH1VA9yZUqLZQu13VR="
flag_out = "S/jeutjaJvhlNA9Du/GaJBhLbQdjd+n1Jy9BcD3="

# Base64 인코딩 알고리즘을 이용해 커스텀 테이블 복원
def recover_custom_table(plaintext, encoded):
    """커스텀 Base64 테이블 복원"""
    standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    custom_table = ['?'] * 64
    
    # 표준 Base64로 인코딩
    standard_encoded = base64.b64encode(plaintext.encode()).decode()
    
    # 매핑 관계 찾기
    for i, (std_char, custom_char) in enumerate(zip(standard_encoded, encoded)):
        if std_char in standard_table:
            idx = standard_table.index(std_char)
            if custom_table[idx] == '?':
                custom_table[idx] = custom_char
            elif custom_table[idx] != custom_char:
                print(f"충돌 발견 at index {idx}: {custom_table[idx]} vs {custom_char}")
    
    return ''.join(custom_table)

# 커스텀 테이블 복원
custom_table = recover_custom_table(text_in, text_out)
print(f"복원된 커스텀 테이블:")
print(custom_table)
print(f"길이: {len([c for c in custom_table if c != '?'])}/64")

# 디코딩 함수
def custom_base64_decode(encoded_text, custom_table):
    """커스텀 Base64 디코딩"""
    standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    # 커스텀 -> 스탠다드 매핑 생성
    trans_table = str.maketrans(custom_table, standard_table)
    
    # 변환 후 디코딩
    standard_encoded = encoded_text.translate(trans_table)
    
    try:
        decoded = base64.b64decode(standard_encoded)
        return decoded.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"디코딩 에러: {e}"

# 검증: text_out 디코딩이 text_in이 되는지 확인
decoded_test = custom_base64_decode(text_out, custom_table)
print(f"\n[검증] text_out 디코딩 결과:")
print(decoded_test)
print(f"\n원본과 일치: {decoded_test == text_in}")

# 플래그 디코딩
print(f"\n{'='*60}")
print(f"플래그 디코딩:")
print(f"{'='*60}")
flag = custom_base64_decode(flag_out, custom_table)
print(f"FLAG: {flag}")