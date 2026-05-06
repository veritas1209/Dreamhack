from pwn import *
from Crypto.Util.number import inverse, bytes_to_long
from hashlib import sha1

def solve_dsa_fixed_k():
    # 서버 환경에 맞게 포트 번호를 수정하세요.
    host = 'host3.dreamhack.games'
    port = 19806
    
    print(f"[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] {host}:{port} 서버에 접속합니다...")
    p = remote(host, port)
    
    # 1. 정보 수집 (p, q, g, y, token)
    # 서버 출력 메뉴 끝부분인 '[3] Get Info'를 대기 기준으로 삼습니다[cite: 17].
    p.sendlineafter(b"[3] Get Info\n", b"3")
    
    p.recvuntil(b"p = ")
    p_val = int(p.recvline().strip())
    p.recvuntil(b"q = ")
    q_val = int(p.recvline().strip())
    p.recvuntil(b"g = ")
    g_val = int(p.recvline().strip())
    p.recvuntil(b"y = ")
    y_val = int(p.recvline().strip())
    
    # token 추출 로직: b'...' 형태로 출력되므로 감싸는 따옴표를 제거합니다[cite: 17].
    p.recvuntil(b"token = b'")
    token = p.recvline().strip().rstrip(b"'")
    
    print(f"[DEBUG] 서버 파라미터 획득 완료!")
    print(f"[DEBUG] 타겟 토큰(token): {token.decode()}")
    
    # 2. 메시지 2개 서명 요청 (연립방정식을 위함)
    msg1 = b"A"
    p.sendlineafter(b"[3] Get Info\n", b"1")
    p.sendlineafter(b"Input message (hex): ", msg1.hex().encode())
    p.recvuntil(b"(")
    r_str, s1_str = p.recvline().strip().strip(b")").split(b", ")
    r = int(r_str)
    s1 = int(s1_str)
    print(f"[DEBUG] msg1('A') 서명 획득 -> r: {r}, s1: {s1}")
    
    msg2 = b"B"
    p.sendlineafter(b"[3] Get Info\n", b"1")
    p.sendlineafter(b"Input message (hex): ", msg2.hex().encode())
    p.recvuntil(b"(")
    _, s2_str = p.recvline().strip().strip(b")").split(b", ")
    s2 = int(s2_str)
    print(f"[DEBUG] msg2('B') 서명 획득 -> s2: {s2}")
    
    # 3. 취약점을 이용한 개인키(x) 계산
    h1 = bytes_to_long(sha1(msg1).digest())
    h2 = bytes_to_long(sha1(msg2).digest())
    
    # x = (s1 - s2) * (h1 - h2)^-1 mod q
    num = (s1 - s2) % q_val
    den = inverse((h1 - h2) % q_val, q_val)
    x = (num * den) % q_val
    
    print(f"\n[DEBUG] 해킹된 개인키(x) 계산 결과: {x}")
    
    # 계산된 개인키 검증: g^x mod p == y[cite: 17]
    if pow(g_val, x, p_val) == y_val:
        print("[DEBUG] 개인키 검증 성공! (완벽히 일치합니다)")
    else:
        print("[ERROR] 개인키 검증 실패! (스크립트를 다시 확인해주세요)")
        return
        
    # 4. 토큰에 대한 위조 서명(Forged Signature) 생성
    h_token = bytes_to_long(sha1(token).digest())
    # s = x * (h + x*r) mod q
    s_token = (x * (h_token + x * r)) % q_val
    print(f"[DEBUG] 타겟 토큰에 대한 위조된 서명(s_token) 생성 완료: {s_token}")
    
    # 5. 서명 검증 요청 및 플래그 획득[cite: 17]
    p.sendlineafter(b"[3] Get Info\n", b"2")
    p.sendlineafter(b"Input message (hex): ", token.hex().encode())
    
    # 주의: 서버 소스 코드의 오타(signagure)를 그대로 반영하여 대기합니다[cite: 17].
    p.sendlineafter(b"integer): ", f"{r}, {s_token}".encode())
    
    p.recvuntil(b"Signature verification success\n")
    flag_raw = p.recvline().strip().decode('utf-8')
    
    # 서버가 b'DH{...}' 형식으로 출력할 경우 깔끔하게 텍스트만 추출
    if flag_raw.startswith("b'") and flag_raw.endswith("'"):
        flag_raw = flag_raw[2:-1]
    
    print(f"\n[DEBUG] ================= 최종 결과 =================")
    print(f"[FLAG] {flag_raw}")
    
    p.close()

if __name__ == '__main__':
    solve_dsa_fixed_k()