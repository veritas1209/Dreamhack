from pwn import *

def solve_aes_no_shiftrows_fixed():
    # 서버 주소 및 포트를 현재 문제 환경에 맞게 입력하세요
    host = 'host8.dreamhack.games'
    port = 17097 
    
    print("[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] 서버 {host}:{port} 에 접속을 시도합니다...")
    p = remote(host, port)
    
    # 1. 서버가 제공하는 secret_enc 수신
    p.recvuntil(b"enc(secret) = ")
    secret_enc_hex = p.recvline().decode('utf-8').strip()
    secret_enc = bytearray.fromhex(secret_enc_hex)
    print(f"[DEBUG] 원본 secret_enc: {secret_enc.hex()}")
    
    # 2. 첫 번째 변조 (0번 인덱스 변경 -> 0~3번 바이트 훼손)
    c1 = bytearray(secret_enc)
    c1[0] ^= 0xFF 
    
    p.sendlineafter(b"[1] encrypt, [2] decrypt: ", b"2")
    p.sendlineafter(b"Input ciphertext to decrypt in hex: ", c1.hex().encode())
    
    p.recvuntil(b"dec(ciphertext) = ")
    p1 = bytes.fromhex(p.recvline().decode('utf-8').strip())
    print(f"[DEBUG] 1차 복호화 (P1): {p1.hex()}")
    print("[DEBUG] -> 4~15번 바이트 평문 완벽 복구!")

    # 3. 두 번째 변조 (4번 인덱스 변경 -> 4~7번 바이트 훼손)
    c2 = bytearray(secret_enc)
    c2[4] ^= 0xFF
    
    p.sendlineafter(b"[1] encrypt, [2] decrypt: ", b"2")
    p.sendlineafter(b"Input ciphertext to decrypt in hex: ", c2.hex().encode())
    
    p.recvuntil(b"dec(ciphertext) = ")
    p2 = bytes.fromhex(p.recvline().decode('utf-8').strip())
    print(f"[DEBUG] 2차 복호화 (P2): {p2.hex()}")
    print("[DEBUG] -> 0~3번 바이트 평문 완벽 복구!")

    # 4. 평문 조립(Stitching)
    # P2에서 멀쩡한 앞부분 4바이트 획득 + P1에서 멀쩡한 뒷부분 12바이트 획득
    secret_recovered = p2[0:4] + p1[4:16]
    print(f"\n[DEBUG] 완벽하게 복구된 secret: {secret_recovered.hex()}")

    # 5. 플래그 획득
    print("\n[DEBUG] --- 플래그 획득 시도 ---")
    p.sendlineafter(b"[1] encrypt, [2] decrypt: ", b"1")
    p.sendlineafter(b"Input plaintext to encrypt in hex: ", secret_recovered.hex().encode())
    
    # enc(plaintext) = ... 출력 라인 무시
    p.recvline() 
    
    # 정답일 경우 서버가 플래그를 뱉고 종료함
    flag = p.recvline().decode('utf-8').strip()
    
    print(f"\n[DEBUG] ================= 최종 결과 =================")
    print(f"[FLAG] {flag}")
    
    p.close()

if __name__ == '__main__':
    solve_aes_no_shiftrows_fixed()