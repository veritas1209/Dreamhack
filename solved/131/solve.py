from pwn import *
from Crypto.Util.number import long_to_bytes, inverse

def solve_rsa_cca():
    # 문제 서버 주소 (환경에 맞게 수정 필요)
    host = 'host8.dreamhack.games'
    port = 21413
    
    print(f"[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] {host}:{port} 서버에 접속합니다...")
    p = remote(host, port)
    
    # 1. 정보 수집 (N, e, FLAG_enc)
    # 수정됨: 서버가 마지막으로 출력하는 메뉴 문자열을 기준으로 기다립니다.
    p.sendlineafter(b"[3] Get info", b"3")
    
    p.recvuntil(b"N: ")
    N = int(p.recvline().strip())
    p.recvuntil(b"e: ")
    e = int(p.recvline().strip())
    p.recvuntil(b"FLAG: ")
    flag_enc = int(p.recvline().strip())
    
    print(f"[DEBUG] 정보 수집 완료!")
    print(f"[DEBUG] N = {str(N)[:30]}... (생략)")
    print(f"[DEBUG] e = {e}")
    print(f"[DEBUG] FLAG_enc = {str(flag_enc)[:30]}... (생략)")
    
    # 2. 암호문 조작 (Blinding)
    multiplier = 2
    multiplier_enc = pow(multiplier, e, N)
    
    blinded_ct = (flag_enc * multiplier_enc) % N
    print(f"\n[DEBUG] 조작된 암호문(C') 생성 완료!")
    
    blinded_ct_hex = hex(blinded_ct)[2:]
    if len(blinded_ct_hex) % 2 != 0:
        blinded_ct_hex = '0' + blinded_ct_hex
        
    print(f"[DEBUG] 16진수 변환: {blinded_ct_hex[:30]}... (생략)")
    
    # 3. 조작된 암호문 복호화 요청
    # 수정됨: 서버가 다시 메뉴를 출력할 때까지 기다립니다.
    p.sendlineafter(b"[3] Get info", b"2")
    
    # 이 부분은 서버 코드에 명확하게 존재하므로 그대로 사용합니다.
    p.sendlineafter(b"Input ciphertext (hex): ", blinded_ct_hex.encode())
    
    blinded_pt = int(p.recvline().strip())
    print(f"\n[DEBUG] 서버로부터 조작된 평문(P') 획득 성공!")
    
    # 4. 플래그 복구 (Unblinding)
    inv_multiplier = inverse(multiplier, N)
    original_flag_int = (blinded_pt * inv_multiplier) % N
    
    print(f"[DEBUG] 원래의 플래그(P) 계산 완료!")
    
    # 5. 정수를 바이트 문자열로 변환하여 플래그 출력
    flag = long_to_bytes(original_flag_int)
    
    print(f"\n[DEBUG] ================= 최종 결과 =================")
    print(f"[FLAG] {flag.decode('utf-8')}")
    
    p.close()

if __name__ == '__main__':
    solve_rsa_cca()