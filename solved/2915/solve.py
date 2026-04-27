import os

# 원본 코드와 동일한 키 사용 (문자열 형태의 bytes 객체)
KEY = b'393e412a6b98c0ead02506105bc06af2c9b06fca919ec77f77f02a9b83ba2d62'
ENC_PATH = "flag.png.bin"
DEC_PATH = "flag.png"

def xor_data(data: bytes, key: bytes):
    print(f"  [>] xor_data 함수 진입")
    print(f"  [>] 입력 데이터 길이: {len(data)} bytes")
    print(f"  [>] 키 길이: {len(key)} bytes")
    print(f"  [>] 키 값 (전체): {key}")
    
    # 연산 전 암호화된 데이터의 앞 16바이트 출력 (비교용)
    print(f"  [>] 연산 전 데이터 (앞 16바이트): {data[:16]}")
    
    # XOR 연산 수행 (원본 코드와 동일한 로직)
    result = bytes((b ^ key[i % len(key)] for i, b in enumerate(data)))
    
    print(f"  [>] XOR 연산 완료!")
    # 연산 후 복호화된 데이터의 앞 16바이트 출력
    print(f"  [>] 연산 후 데이터 (앞 16바이트): {result[:16]}")
    
    # PNG 파일의 매직 넘버(시그니처)가 제대로 복원되었는지 확인
    # 정상적인 PNG라면 앞 8바이트가 b'\x89PNG\r\n\x1a\n' 이어야 합니다.
    print(f"  [>] PNG 매직 넘버 확인 (예상: b'\\x89PNG\\r\\n\\x1a\\n') -> 결과: {result[:8]}")
    
    if result[:8] == b'\x89PNG\r\n\x1a\n':
        print(f"  [+] PNG 시그니처가 정확하게 일치합니다! 복호화가 성공적인 것 같습니다.")
    else:
        print(f"  [-] 경고: PNG 시그니처가 일치하지 않습니다. 복호화에 문제가 있을 수 있습니다.")
        
    return result

def decrypt_png():
    print(f"[*] 복호화 프로세스 시작")
    print("-" * 50)
    
    if not os.path.exists(ENC_PATH):
        print(f"[-] 오류: '{ENC_PATH}' 파일을 찾을 수 없습니다. 경로를 확인해 주세요.")
        return

    print(f"[*] 1. '{ENC_PATH}' 파일을 읽어옵니다.")
    with open(ENC_PATH, "rb") as f:
        encrypted_data = f.read()
    
    print(f"[*] 파일 읽기 완료 (총 {len(encrypted_data)} bytes)")
    print("-" * 50)
    
    print(f"[*] 2. 데이터 복호화(XOR)를 진행합니다.")
    decrypted_data = xor_data(encrypted_data, KEY)
    print("-" * 50)
    
    print(f"[*] 3. 복호화된 데이터를 '{DEC_PATH}' 파일로 저장합니다.")
    with open(DEC_PATH, "wb") as f:
        f.write(decrypted_data)
    
    print(f"[+] 모든 과정 완료! '{DEC_PATH}' 파일을 열어서 Flag를 확인해 보세요.")

if __name__ == "__main__":
    decrypt_png()