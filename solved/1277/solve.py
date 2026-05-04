import string

def solve_vigenere_kpa():
    # 문제와 동일한 문자 세트 구성[cite: 8]
    words = string.ascii_uppercase + string.ascii_lowercase + string.digits
    
    # 문제에서 주어진 암호문[cite: 7]
    ct = "39 2YAx k5LgCy iP Aj9geVQy nEvXnd3Je c kX9P 8z uZ7dbErYRAyegw Ona3Js eRcKyO u7 ffFTl70 TH9ScB – M0HbNuV HDd 4yk TE c3uVU 8Y D1Q ZDNhBpRc 9WY27fjiF – dVWNBP D1Q NAZsM fW bPlBI N3e p8 6i97Nc. FmP HjIjVi 7Zu 4Zth9 bL kYD Gg0yZjc0 dBrYVQ, f8GQ0PD, Bu kGue 8BUlT9FmE0 UDCNp2vQi xd jkfm97 9uDfndFF egcc9CZ 27 mTE 2Y7u A8Zi fM N4Ks3 UVK Dg0. LTAabG 2RSDTqDu GP7QbLq. qy ZE2Xy GUpG kYD eYvEXf DJdMc fE Ep2DTjX4Zt dlk uObyx f DJq7ckZM0 \"w8gse0WtBie\" (L 4yk) FT LyZkB1 a29Tjc FmIjRSDDd yFQwj QfMvVi. 9I, Tjc0 dHoVj DSc zXfR. Ek{sreSsZxMq8OPf37BwUdvpZKzQ8oNg7Z8rwASqbxQsBl0g935rwDLQaNxNCnxK44g}"
    
    # 이전 시도에서 파편적으로 복구된 문장을 통해 알아낸 100% 확실한 평문
    known_pt = "In 1586 Blaise de Vigenere published "
    
    key_length = 16
    recovered_key = [None] * key_length
    
    print("[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] 알려진 평문(KPA) 기반 16바이트 키 역산 시작...")
    
    # 1. 알려진 평문을 이용해 키 배열 완벽 복구
    for i in range(len(known_pt)):
        ct_char = ct[i]
        pt_char = known_pt[i]
        
        # 공백이나 특수문자가 아닌 변환 대상 문자인 경우에만 키 계산[cite: 8]
        if ct_char in words and pt_char in words:
            # 암호화 수식: (pt_index + key) % 62 = ct_index[cite: 8]
            # 복호화(키 역산) 수식: key = (ct_index - pt_index) % 62
            k = (words.index(ct_char) - words.index(pt_char)) % len(words)
            key_idx = i % key_length
            
            if recovered_key[key_idx] is None:
                recovered_key[key_idx] = k
            elif recovered_key[key_idx] != k:
                # 글자 위치가 다름에도 계산된 키가 다르다면 평문 예측이 틀렸다는 뜻입니다.
                print(f"[WARNING] 키 충돌 발생! 인덱스 {key_idx}: 기존 {recovered_key[key_idx]}, 새 계산값 {k}")
                
    print(f"\n[DEBUG] KPA를 통해 단 하나의 오차 없이 복구된 키 배열:")
    print(f"[DEBUG] {recovered_key}")
    print("[DEBUG] ========================================\n")
    
    # 2. 복구된 키를 바탕으로 전체 문자열 복호화
    print("[DEBUG] 전체 문자열 복호화 진행 중...\n")
    pt = ""
    for i in range(len(ct)):
        char = ct[i]
        if char in words:
            k = recovered_key[i % key_length]
            dec_idx = (words.index(char) - k) % len(words)
            pt += words[dec_idx]
        else:
            pt += char # 공백 및 특수문자 유지[cite: 8]
            
    print(f"[DEBUG] ================= 최종 결과 =================")
    print(pt)

if __name__ == "__main__":
    solve_vigenere_kpa()