import hashlib
import random

def a(data: bytes, uk: bytes) -> bytes:
    """Shuffle function - 바이트 순서를 섞음"""
    seed = int.from_bytes(hashlib.md5(uk).digest(), 'big')
    random.seed(seed)
    indices = list(range(len(data)))
    random.shuffle(indices)
    return bytes([data[i] for i in indices])

def b(data: bytes, k: bytes) -> bytes:
    """XOR encryption function"""
    k_stream = hashlib.sha256(k).digest()
    return bytes([b ^ k_stream[i % len(k_stream)] for i, b in enumerate(data)])

def c(data: bytes, k: bytes) -> bytes:
    """Main encryption function"""
    uk = b"cry_me_a_river"
    ad = a(data, uk)
    y = b(ad, k)
    return y

def find_shuffle_mapping(length: int) -> list:
    """원본 인덱스가 shuffle 후 어디로 가는지 매핑 찾기"""
    uk = b"cry_me_a_river"
    seed = int.from_bytes(hashlib.md5(uk).digest(), 'big')
    random.seed(seed)
    indices = list(range(length))
    random.shuffle(indices)
    
    # 역매핑 생성 (원본 위치 -> shuffle 후 위치)
    mapping = [0] * length
    for new_pos, old_pos in enumerate(indices):
        mapping[old_pos] = new_pos
    return mapping

def decrypt(ciphertext: bytes, k: bytes) -> bytes:
    """복호화 함수"""
    uk = b"cry_me_a_river"
    
    # 1. XOR 복호화
    k_stream = hashlib.sha256(k).digest()
    xor_decrypted = bytes([b ^ k_stream[i % len(k_stream)] for i, b in enumerate(ciphertext)])
    
    # 2. Unshuffle - shuffle의 역연산
    seed = int.from_bytes(hashlib.md5(uk).digest(), 'big')
    random.seed(seed)
    indices = list(range(len(xor_decrypted)))
    random.shuffle(indices)
    
    # 역순으로 배치
    unshuffled = [0] * len(xor_decrypted)
    for new_pos, old_pos in enumerate(indices):
        unshuffled[old_pos] = xor_decrypted[new_pos]
    
    return bytes(unshuffled)

def solve_ctf(ciphertext: bytes):
    """CTF 문제 해결"""
    print("[*] CTF 랜섬웨어 문제 해결 시작")
    print(f"[*] 암호문 길이: {len(ciphertext)} bytes")
    
    # 첫 글자 'C'가 shuffle 후 어느 위치로 가는지 확인
    mapping = find_shuffle_mapping(len(ciphertext))
    first_char_pos = mapping[0]
    print(f"[*] 'C'(첫 글자)는 shuffle 후 인덱스 {first_char_pos}로 이동")
    
    # 가능한 플래그 형식
    flag_prefix = b"DH{cry_m3_4_r1v3r_0x"
    
    print("\n[*] Brute force 시작 (0x000000 ~ 0xffffff)")
    print("[*] 이 작업은 시간이 걸릴 수 있습니다...")
    
    found = False
    for i in range(0x1000000):  # 0x000000 ~ 0xffffff
        if i % 0x10000 == 0:
            print(f"[*] 진행 중: 0x{i:06x}")
        
        # 후보 키 생성
        candidate_key = flag_prefix + f"{i:06x}".encode() + b"}"
        
        # 복호화 시도
        try:
            decrypted = decrypt(ciphertext, candidate_key)
            
            # 첫 글자가 'C'인지 확인
            if decrypted[0] == ord('C'):
                # 추가 검증: ASCII 출력 가능한 문자인지, 그리고 발표 자료로 보이는지
                try:
                    # 최소 100바이트는 읽을 수 있는 텍스트여야 함
                    sample = decrypted[:min(500, len(decrypted))]
                    if all(32 <= byte <= 126 or byte in [9, 10, 13] for byte in sample):
                        # UTF-8 디코딩 시도
                        text_sample = decrypted.decode('utf-8', errors='strict')
                        
                        print(f"\n[!] 가능한 플래그 발견: {candidate_key.decode()}")
                        print(f"[!] 복호화된 텍스트 (처음 500자):")
                        print("-" * 50)
                        print(text_sample[:500])
                        print("-" * 50)
                        
                        # 파일로 저장
                        output_filename = f"decrypted_0x{i:06x}.txt"
                        with open(output_filename, "wb") as f:
                            f.write(decrypted)
                        print(f"[!] 복호화된 파일 저장: {output_filename}")
                        
                        # 발표 자료 관련 키워드 체크
                        keywords = ['발표', '과제', '슬라이드', 'presentation', 'slide', 'PPT', '목차', '서론', '결론']
                        text_lower = text_sample.lower()
                        found_keywords = [kw for kw in keywords if kw.lower() in text_lower]
                        if found_keywords:
                            print(f"[!] 발표 자료 키워드 발견: {found_keywords}")
                            found = True
                            break  # 찾았으면 중단
                        else:
                            print("[*] 발표 자료 키워드가 없음 - 계속 검색...")
                            
                except UnicodeDecodeError:
                    pass  # UTF-8이 아닌 경우 무시
                except Exception:
                    pass
                    
        except Exception as e:
            continue
    
    if not found:
        print("\n[-] 플래그를 찾지 못했습니다.")
        print("[*] 디버깅 정보:")
        
        # 테스트용 암호화/복호화
        test_key = b"DH{cry_m3_4_r1v3r_0x123456}"
        test_plain = b"CTF is fun!"
        test_cipher = c(test_plain, test_key)
        test_decrypt = decrypt(test_cipher, test_key)
        print(f"[*] 테스트 - 원본: {test_plain}")
        print(f"[*] 테스트 - 복호화: {test_decrypt}")
        print(f"[*] 테스트 성공: {test_plain == test_decrypt}")

# 사용 예시
if __name__ == "__main__":
    # 암호화된 파일을 읽어오기
    with open(r"C:\Users\hajin\hacking_study\dreamhack\2279\encrypted_file", "rb") as f:
        ciphertext = f.read()
    
    # 테스트용 암호화
    #test_key = b"DH{cry_m3_4_r1v3r_0x1a2b3c}"
    #test_plaintext = b"CTF challenges are interesting and educational!"
    #ciphertext = c(test_plaintext, test_key)
    
    print(f"[*] 테스트 암호문: {ciphertext.hex()[:50]}...")
    
    # 문제 해결
    solve_ctf(ciphertext)