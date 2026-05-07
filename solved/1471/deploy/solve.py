#!/usr/bin/env python3
import sys
import struct
import random
from pwn import *

# GHOST S-box 정의
SBOX = (
    (0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1),
    (0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF),
    (0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0),
    (0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB),
    (0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC),
    (0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0),
    (0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7),
    (0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2)
)

def inv_sub_int(v: int) -> int:
    """O(1) 역 S-Box 연산"""
    res = 0
    for i in range(8):
        nib = (v >> (i * 4)) & 0xF
        s_nib = SBOX[i].index(nib)
        res |= (s_nib << (i * 4))
    return res

def ror11(v: int) -> int:
    """11비트 우측 회전 (rol11의 역연산)"""
    return ((v >> 11) | (v << (32 - 11))) & 0xFFFFFFFF

def find_K(A: int, V: int) -> int:
    """V = f_K(A) 일 때, 수학적으로 K를 역산해내는 함수"""
    Y = ror11(V)
    X = inv_sub_int(Y)
    K = (X - A) & 0xFFFFFFFF
    return K

def process_batch(p, command, hex_inputs, prefix=""):
    """초고속 2000개 단위 Chunk 통신"""
    res = []
    chunk_size = 2000
    total = len(hex_inputs)
    target_prompt = b'ciphertext(hex)> ' if command == b'1' else b'plaintext(hex)> '
    
    for i in range(0, total, chunk_size):
        chunk = hex_inputs[i:i+chunk_size]
        payload = b"".join([command + b"\n" + data.encode() + b"\n" for data in chunk])
        
        p.send(payload)
        for _ in range(len(chunk)):
            p.recvuntil(target_prompt)
            res.append(p.recvline().strip().decode())
            
        sys.stdout.write(f"\r  [VERBOSE] {prefix} Oracle 통신 중... ({min(i + chunk_size, total)} / {total})")
        sys.stdout.flush()
    print()
    return res

def main():
    HOST = 'host3.dreamhack.games'
    PORT = 16086
    p = remote(HOST, PORT)

    print("\n[!] 서버 접속 완료. 암호화된 플래그 획득 중...")
    p.sendlineafter(b'> ', b'3')
    p.recvuntil(b'encrypted_flag(hex)> ')
    enc_flag_hex = p.recvline().strip().decode()
    print(f"  -> {enc_flag_hex[:40]}...\n")

    print("="*60)
    print(" [🔥] Slide with a Twist: 완벽 교차 수학 매칭 시작")
    print("="*60)

    # N = 120,000 이면 충돌 확률 약 96.5% (두 키 모두 찾을 확률 93% 이상)
    N = 120000 
    L_vals = [random.getrandbits(32) for _ in range(N)]
    X_vals = [random.getrandbits(32) for _ in range(N)]

    P_A = [f"{L:08x}00000000" for L in L_vals]
    P_B = [f"00000000{X:08x}" for X in X_vals]

    print("[*] 1단계: 난수 페이로드 전송 및 쌍방향 Oracle 수집")
    EA = process_batch(p, b'1', P_A, "Encrypt (Set A)")
    DB = process_batch(p, b'2', P_B, "Decrypt (Set B)")
    DA = process_batch(p, b'2', P_A, "Decrypt (Set A)")
    EB = process_batch(p, b'1', P_B, "Encrypt (Set B)")

    K0, K1 = None, None

    # ----------------------------------------------------
    # Phase 1: K0 역산 (EA 와 DB 의 교차)
    # ----------------------------------------------------
    print("\n[*] 2단계: K0 (Round Key 0) 역산 중...")
    L_C_dict = {}
    for i, ct in enumerate(EA):
        L_C = int(ct[:8], 16) # Encrypt의 Left Half
        if L_C not in L_C_dict: L_C_dict[L_C] = []
        L_C_dict[L_C].append(i)

    for j, dt in enumerate(DB):
        R_C_prime = int(dt[8:], 16) # Decrypt의 Right Half
        if R_C_prime in L_C_dict:   # 핵심: Encrypt_Left == Decrypt_Right 매칭
            for i in L_C_dict[R_C_prime]:
                L_i, X_j = L_vals[i], X_vals[j]
                L_C, R_C = int(EA[i][:8], 16), int(EA[i][8:], 16)
                L_C_prime, R_C_prime_val = int(dt[:8], 16), int(dt[8:], 16)
                
                # 수학적 쌍방향 교차 검증 (가짜 충돌 100% 필터링)
                K0_P = find_K(0, X_j ^ L_i)
                K0_C = find_K(L_C, L_C_prime ^ R_C)
                if K0_P == K0_C:
                    K0 = K0_P
                    print(f"  [★] 완벽한 K0 슬라이드 쌍 발견! K0 = {hex(K0)}")
                    break
        if K0 is not None: break

    # ----------------------------------------------------
    # Phase 2: K1 역산 (DA 와 EB 의 교차)
    # ----------------------------------------------------
    print("\n[*] 3단계: K1 (Round Key 1) 역산 중...")
    L_C_dict_2 = {}
    for i, ct in enumerate(DA):
        L_C = int(ct[:8], 16) # Decrypt의 Left Half
        if L_C not in L_C_dict_2: L_C_dict_2[L_C] = []
        L_C_dict_2[L_C].append(i)

    for j, ct in enumerate(EB):
        R_C_prime = int(ct[8:], 16) # Encrypt의 Right Half
        if R_C_prime in L_C_dict_2: # 핵심: Decrypt_Left == Encrypt_Right 매칭
            for i in L_C_dict_2[R_C_prime]:
                L_i, X_j = L_vals[i], X_vals[j]
                L_C, R_C = int(DA[i][:8], 16), int(DA[i][8:], 16)
                L_C_prime, R_C_prime_val = int(ct[:8], 16), int(ct[8:], 16)
                
                K1_P = find_K(0, X_j ^ L_i)
                K1_C = find_K(L_C, L_C_prime ^ R_C)
                if K1_P == K1_C:
                    K1 = K1_P
                    print(f"  [★] 완벽한 K1 슬라이드 쌍 발견! K1 = {hex(K1)}")
                    break
        if K1 is not None: break

    if K0 is None or K1 is None:
        print("\n[-] 매치를 찾지 못했습니다. 96% 확률을 비껴간 엄청난 운입니다. 스크립트를 한 번만 더 실행해주세요.")
        sys.exit(1)

    # ----------------------------------------------------
    # Phase 3: 최종 플래그 복호화
    # ----------------------------------------------------
    print("\n" + "="*60)
    orig_key = struct.pack('>II', K0, K1)
    print(f"[!] 64-bit Original Key 복원 성공: {orig_key.hex()}")
    
    xor_target = bytes.fromhex('deadbeefcafebabe')
    new_key = bytes([x ^ y for x, y in zip(orig_key, xor_target)])
    print(f"[!] Flag 복호화용 New Key: {new_key.hex()}")
    
    try:
        from cipher import GHOST
        g_final = GHOST(new_key)
        flag = g_final.decrypt(bytes.fromhex(enc_flag_hex))
        print("\n🎉 최종 획득한 FLAG: " + flag.decode('utf-8'))
        print("="*60)
    except Exception as e:
        print(f"[-] 플래그 복호화 중 오류 발생: {e}")

    p.close()

if __name__ == '__main__':
    main()