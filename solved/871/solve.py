from pwn import *
import sympy
from Crypto.Util.number import inverse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import codecs
import base64

def solve_3cipher():
    # 서버 주소 (환경에 맞게 수정해주세요)
    host = 'host3.dreamhack.games'
    port = 9343
    
    print(f"[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] {host}:{port} 서버에 접속합니다...")
    p = remote(host, port)
    
    # 1. 서버로부터 암호화된 데이터들 수신
    p.recvuntil(b"Key1: ")
    key1_hex = p.recvline().strip().decode()
    c1 = int(key1_hex, 16)
    
    p.recvuntil(b"Key2: ")
    key2_rot13 = p.recvline().strip().decode()
    
    p.recvuntil(b"AES_iv: ")
    aes_iv_b64 = p.recvline().strip().decode()
    
    p.recvuntil(b"AES_cipher_text: ")
    aes_ct_b64 = p.recvline().strip().decode()
    
    print("[DEBUG] 데이터 수신 완료!")
    print(f"[DEBUG] Key1 (RSA)  : {key1_hex}")
    print(f"[DEBUG] Key2 (ROT13): {key2_rot13}")
    
    # 2. Key1 복호화 (매우 작은 RSA 모듈러스 소인수분해)[cite: 18]
    n = 13119132709177697801
    e = 65537
    print(f"\n[DEBUG] RSA 모듈러스 N ({n}) 소인수분해 진행 중... (sympy 사용)")
    factors = list(sympy.factorint(n).keys())
    p_prime, q_prime = factors[0], factors[1]
    print(f"[DEBUG] 소인수분해 성공! p = {p_prime}, q = {q_prime}")
    
    # 개인키 d 계산 및 RSA 복호화
    phi = (p_prime - 1) * (q_prime - 1)
    d = inverse(e, phi)
    rc_p_int = pow(c1, d, n)
    rc_p = hex(rc_p_int)[2:]
    print(f"[DEBUG] Key1(앞부분) 복호화 완료: {rc_p}")
    
    # 3. Key2 복호화 (ROT13 역연산)[cite: 18]
    cc_p = codecs.encode(key2_rot13, 'rot_13')
    print(f"[DEBUG] Key2(뒷부분) 복호화 완료: {cc_p}")
    
    # 4. AES 키 완벽 재구성 및 플래그 복호화
    # 앞부분과 뒷부분의 16진수 문자열을 합친 후 원래의 바이트 배열(16바이트)로 변환합니다.
    ac_key_hex = rc_p + cc_p
    ac_key_int = int(ac_key_hex, 16)
    ac_key_bytes = ac_key_int.to_bytes(16, 'big')
    print(f"\n[DEBUG] 재구성된 AES 16바이트 키: {ac_key_bytes.hex()}")
    
    iv = base64.b64decode(aes_iv_b64)
    ct = base64.b64decode(aes_ct_b64)
    
    # 복구한 키와 iv를 이용해 AES-CBC 복호화[cite: 18]
    cipher = AES.new(ac_key_bytes, AES.MODE_CBC, iv)
    flag = unpad(cipher.decrypt(ct), 16)
    
    print(f"\n[DEBUG] ================= 최종 결과 =================")
    print(f"[FLAG] {flag.decode('utf-8')}")
    
    p.close()

if __name__ == '__main__':
    solve_3cipher()