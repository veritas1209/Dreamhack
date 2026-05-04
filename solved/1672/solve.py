from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

def solve_dh_mitm():
    # 서버 접속 정보
    host = 'host8.dreamhack.games'
    port = 18357
    
    print(f"[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] {host}:{port} 서버에 접속합니다...")
    p_conn = remote(host, port)
    
    # 1. 소수 p(Prime) 획득
    p_conn.recvuntil(b"Prime: ")
    p = int(p_conn.recvline().strip(), 16)
    print(f"[DEBUG] 소수 p 획득 완료!")
    
    # 2. 앨리스의 공개키(A) 가로채기
    p_conn.recvuntil(b"Alice sends her key to Bob. Key: ")
    A = int(p_conn.recvline().strip(), 16)
    print(f"[DEBUG] 앨리스의 원본 공개키(A) 획득!")
    
    # 3. 밥에게 가짜 키(g^2 = 4) 전송[cite: 12]
    p_conn.sendlineafter(b">> ", b"4")
    print(f"[DEBUG] 밥에게 가짜 공개키 '4' 전송 완료 (필터링 우회)")
    
    # 4. 밥의 공개키(B) 가로채기
    p_conn.recvuntil(b"Bob sends his key to Alice. Key: ")
    B = int(p_conn.recvline().strip(), 16)
    print(f"[DEBUG] 밥의 원본 공개키(B) 획득!")
    
    # 5. 앨리스에게 가짜 키(g^2 = 4) 전송[cite: 12]
    p_conn.sendlineafter(b">> ", b"4")
    print(f"[DEBUG] 앨리스에게 가짜 공개키 '4' 전송 완료 (필터링 우회)")
    
    # 6. 각자의 공유 비밀키 계산 (A^2 % p, B^2 % p)
    S_A = pow(A, 2, p)
    S_B = pow(B, 2, p)
    print(f"\n[DEBUG] 해킹된 공유 비밀키 계산 완료!")
    print(f"[DEBUG] 앨리스가 쓸 비밀키 (S_A): {str(S_A)[:30]}... (생략)")
    print(f"[DEBUG] 밥이 쓸 비밀키 (S_B): {str(S_B)[:30]}... (생략)")
    
    # 7. 암호화된 플래그 조각들 수신
    p_conn.recvuntil(b"Alice: ")
    alice_ct = bytes.fromhex(p_conn.recvline().strip().decode())
    
    p_conn.recvuntil(b"Bob: ")
    bob_ct = bytes.fromhex(p_conn.recvline().strip().decode())
    
    print(f"\n[DEBUG] 암호화된 플래그 수신 완료. 복호화를 시작합니다...")
    
    # 8. 앨리스의 플래그 조각 복호화[cite: 12]
    key_A = hashlib.md5(str(S_A).encode()).digest()
    cipher_A = AES.new(key_A, AES.MODE_ECB)
    pt_A = unpad(cipher_A.decrypt(alice_ct), 16)
    
    # 9. 밥의 플래그 조각 복호화[cite: 12]
    key_B = hashlib.md5(str(S_B).encode()).digest()
    cipher_B = AES.new(key_B, AES.MODE_ECB)
    pt_B = unpad(cipher_B.decrypt(bob_ct), 16)
    
    # 10. 플래그 결합
    flag = pt_A + pt_B
    
    print(f"\n[DEBUG] ================= 최종 결과 =================")
    print(f"[FLAG] {flag.decode('utf-8')}")
    
    p_conn.close()

if __name__ == "__main__":
    solve_dh_mitm()