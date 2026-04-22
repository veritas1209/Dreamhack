from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 통신 과정을 자세히 볼 수 있도록 pwntools 로그 레벨 설정 (필요시 'info'로 변경)
context.log_level = 'debug'

def solve():
    print("\n[+] ==========================================")
    print("[+] 드림핵 Textbook-CBC 익스플로잇을 시작합니다.")
    print("[+] ==========================================\n")
    
    host = "host3.dreamhack.games"
    port = 13767
    
    print(f"[*] 타겟 서버 {host}:{port} 에 연결 중...")
    p = remote(host, port)

    # ---------------------------------------------------------
    # 1. 16바이트 평문 암호화 요청하여 C1, C2 획득
    # ---------------------------------------------------------
    p.recvuntil(b"[3] Get Flag\n")
    print("[*] 1번 메뉴(Encrypt) 선택")
    p.sendline(b"1")
    
    p.recvuntil(b"Input plaintext (hex): ")
    # 16바이트의 임의의 평문(P1) 전송
    pt_hex = (b"A" * 16).hex()
    print(f"[*] 암호화 요청 평문 (hex) : {pt_hex}")
    p.sendline(pt_hex.encode())
    
    ct_hex = p.recvline().strip().decode()
    print(f"[*] 암호화 결과 수신 (hex) : {ct_hex}")
    
    # 16바이트를 암호화하면 패딩을 포함해 32바이트(64자리 헥스)가 반환됨
    c1_hex = ct_hex[:32]
    c2_hex = ct_hex[32:]
    zero_hex = "00" * 16  # 16바이트 0 (32자리 헥스)
    
    # ---------------------------------------------------------
    # 2. 복호화 오라클 우회를 위한 페이로드 구성 및 전송
    # ---------------------------------------------------------
    payload_hex = c1_hex + zero_hex + c1_hex + c2_hex
    print("\n[*] 복호화 오라클에 전송할 페이로드 조립 (C1 || 0^16 || C1 || C2)")
    print(f"    -> C1   : {c1_hex}")
    print(f"    -> 0^16 : {zero_hex}")
    print(f"    -> C1   : {c1_hex}")
    print(f"    -> C2   : {c2_hex}")
    print(f"[*] 최종 전송 페이로드 : {payload_hex}")
    
    p.recvuntil(b"[3] Get Flag\n")
    print("[*] 2번 메뉴(Decrypt) 선택")
    p.sendline(b"2")
    
    p.recvuntil(b"Input ciphertext (hex): ")
    p.sendline(payload_hex.encode())
    
    dec_hex = p.recvline().strip().decode()
    print(f"[*] 조작된 암호문 복호화 결과 수신 : {dec_hex}")
    
    # ---------------------------------------------------------
    # 3. 반환된 평문을 이용해 Key(=IV) 복구
    # ---------------------------------------------------------
    # dec_hex는 P'_1 || P'_2 || P'_3 를 포함함 (C2는 패딩으로 떨어져 나감)
    p1_prime = bytes.fromhex(dec_hex[:32])
    p3_prime = bytes.fromhex(dec_hex[64:96])
    
    print("\n[*] Key 복구를 위한 블록 추출")
    print(f"    -> P'_1 (첫 번째 블록) : {p1_prime.hex()}")
    print(f"    -> P'_3 (세 번째 블록) : {p3_prime.hex()}")
    
    # Key 추출: P'_1 XOR P'_3
    key = bytes([a ^ b for a, b in zip(p1_prime, p3_prime)])
    print(f"\n[+] ★★★ 성공적으로 Key(=IV)를 복구했습니다! ★★★")
    print(f"    -> 복구된 Key (hex) : {key.hex()}")
    
    # ---------------------------------------------------------
    # 4. 암호화된 플래그 획득
    # ---------------------------------------------------------
    p.recvuntil(b"[3] Get Flag\n")
    print("\n[*] 3번 메뉴(Get Flag) 선택")
    p.sendline(b"3")
    
    p.recvuntil(b"flag = ")
    flag_enc_hex = p.recvline().strip().decode()
    print(f"[*] 서버로부터 암호화된 플래그 획득 : {flag_enc_hex}")
    
    # ---------------------------------------------------------
    # 5. 로컬에서 복구한 Key로 플래그 복호화
    # ---------------------------------------------------------
    print("[*] 복구한 Key를 이용하여 로컬에서 플래그 복호화 진행 중...")
    cipher = AES.new(key, AES.MODE_CBC, key)
    try:
        flag_dec = unpad(cipher.decrypt(bytes.fromhex(flag_enc_hex)), 16)
        print(f"\n[+] ==========================================")
        print(f"[+] 최종 획득한 플래그 : {flag_dec.decode()}")
        print("[+] ==========================================\n")
    except ValueError as e:
        print(f"[-] 플래그 복호화 중 오류 발생 (패딩 에러 등): {e}")

if __name__ == "__main__":
    solve()