#!/usr/bin/env sage
from sage.all import *
from pwn import *
import sys

# 디버깅 출력을 위한 설정
context.log_level = 'debug'

def solve():
    print("[*] 1단계: 악의적인 n과 F(factor) 생성 시작...")
    
    # 1. R을 510비트 정도로 맞춥니다. (512비트가 넘지 않도록 주의)
    R = 1
    p_val = 2
    primes_used = []
    # 다음 소수를 곱했을 때 510비트를 넘지 않을 때까지만 곱함
    while (R * p_val).nbits() <= 510:
        R *= p_val
        primes_used.append(p_val)
        p_val = next_prime(p_val)
    
    print(f"[*] 생성된 Smooth Number R (비트수: {R.nbits()}): {R}")
    print(f"[*] R을 구성하는 가장 큰 소수: {primes_used[-1]}")

    # 2. n이 정확히 1024비트가 되기 위한 F의 탐색 범위를 수학적으로 계산
    # 2^1023 <= n < 2^1024 이어야 하므로, 이를 만족하는 F의 범위를 도출
    F_min = (2**1023) // R + 1
    F_max = (2**1024 - 1) // R
    
    print(f"[*] 계산된 F의 탐색 범위: {F_min.nbits()} ~ {F_max.nbits()} bits")
    print(f"[*] 조건을 만족하는 F와 n을 찾는 중 (n = F * R + 1)...")
    
    attempt = 0
    while True:
        attempt += 1
        # 수학적으로 계산된 범위 내에서 F를 뽑으므로 n은 무조건 1024비트가 됨
        F = random_prime(F_max, lbound=F_min)
        n = F * R + 1
        
        # 이제 n이 소수인지만 확인하면 끝
        if n.is_prime():
            print(f"    -> [SUCCESS] {attempt}번의 시도 만에 완벽한 n 발견!")
            break
            
        if attempt % 50 == 0:
            print(f"    -> {attempt}번 시도 중... (조금만 기다려주세요)")
            
    print(f"[+] 최종 발견된 n (비트수: {n.nbits()}): {n}")
    print(f"[+] 최종 발견된 factor F (비트수: {F.nbits()}): {F}")

    # 서버 연결 (CTF 환경에 맞게 호스트/포트 수정 필요)
    print("[*] 서버 접속 시도 중...")
    r = remote('host3.dreamhack.games', 22100) 
    
    print("[*] 서버에 조작된 n과 factor 전송...")
    r.sendlineafter(b"Give me n: ", str(n).encode())
    r.sendlineafter(b"Give me a large prime factor of n - 1: ", str(F).encode())
    
    # 데이터 파싱
    print("[*] 서버로부터 공개키(Pubkey) 및 암호문 수신 중...")
    r.recvuntil(b"Pubkey: ")
    pubkey_str = r.recvline().decode().strip()
    
    # 파이썬 리스트 형태의 공개키 v 추출
    v_list_str = pubkey_str[pubkey_str.find('['):pubkey_str.find(']')+1]
    v_list = eval(v_list_str)
    print(f"[*] 공개키 배열 파싱 완료 (길이: {len(v_list)})")
    
    r.recvuntil(b"Plaintext len: ")
    pt_len = int(r.recvline().strip())
    num_vars = pt_len * 8  # 사용된 실제 평문의 비트 길이
    print(f"[*] 평문 길이: {pt_len} bytes -> LLL 적용 변수 개수: {num_vars} 개")
    
    r.recvuntil(b"Encrypted result: ")
    c = int(r.recvline().strip())
    print(f"[*] 암호문 c: {c}")

    # ============================================================
    print("\n[*] 2단계: Pohlig-Hellman을 이용한 이산 로그 계산 시작...")
    Z_n = IntegerModRing(n)
    
    print("[*] 위수가 R인 생성자(generator) h 찾는 중...")
    while True:
        g = Z_n.random_element()
        h = g**F
        is_gen = True
        # R의 모든 소인수에 대해 위수 검증
        for q, _ in R.factor():
            if h**(R // q) == 1:
                is_gen = False
                break
        if is_gen:
            break
    print(f"[+] 생성자 h 발견 완료!")

    print("[*] 각 v_i와 암호문 c에 대한 이산 로그 계산 중 (R이 Smooth 하므로 즉시 연산됨)...")
    L_list = []
    for i in range(num_vars):
        # 모듈러 R의 세계로 매핑하기 위해 F승
        w_i = Z_n(v_list[i])**F
        l_i = discrete_log(w_i, h, ord=R)
        L_list.append(l_i)
        
        if (i+1) % 20 == 0:
            print(f"    - {i+1}/{num_vars} 개 계산 완료")
            
    w_c = Z_n(c)**F
    L_c = discrete_log(w_c, h, ord=R)
    print(f"[+] 목표 값의 이산 로그(L_c) 계산 완료: {L_c}")

    # ============================================================
    print("\n[*] 3단계: LLL 알고리즘을 사용한 Subset Sum 격자(Lattice) 구성 및 축소...")
    
    # LLL이 타겟 벡터를 절대 놓치지 않도록 가중치를 압도적으로 큰 값(R 자체)으로 설정합니다.
    W = R 
    
    # 변수 개수는 128개 (pt_len * 8)
    M = Matrix(ZZ, num_vars + 2, num_vars + 2)
    
    for i in range(num_vars):
        M[i, i] = 2
        M[i, num_vars + 1] = L_list[i] * W
        
    M[num_vars, num_vars] = 1
    for i in range(num_vars):
        M[num_vars, i] = -1
    M[num_vars, num_vars + 1] = -L_c * W
    
    M[num_vars + 1, num_vars + 1] = R * W
    
    print("[*] LLL 기반 격자 기저 축소 실행 중...")
    B = M.LLL()
    print("[+] LLL 축소 완료! 결과 벡터 탐색 중...")
    
    m_int = None
    best_diff = 99999  # 디버깅용 오답 비트 개수 추적
    
    for row in B:
        # 마지막 열(subset sum 결과)이 0이고, 타겟 승수가 1 또는 -1인지 확인
        if row[num_vars + 1] == 0 and abs(row[num_vars]) == 1:
            if row[num_vars] == -1:
                row = -row
            
            # 현재 벡터에서 1이나 -1이 아닌(오답인) 비트의 개수 카운팅
            wrong_count = sum(1 for i in range(num_vars) if abs(row[i]) != 1)
            if wrong_count < best_diff:
                best_diff = wrong_count
                
            if wrong_count == 0:
                print("[+] 완벽한 타겟 벡터를 찾았습니다!")
                # LLL 결과로부터 원본 비트 복원
                bits = [(row[i] + 1) // 2 for i in range(num_vars)]
                m_int = sum([int(bits[i]) * (2**i) for i in range(num_vars)])
                break
                
    if m_int is None:
        print(f"[-] LLL로 완벽한 타겟 벡터를 찾지 못했습니다. (최소 오답 비트 수: {best_diff}개)")
        print("[*] 더 강력한 BKZ 알고리즘으로 격자 축소를 재시도합니다... (시간이 조금 걸릴 수 있습니다)")
        
        # LLL보다 훨씬 강력한 BKZ 알고리즘 적용 (block_size=15)
        B = M.BKZ(block_size=15)
        for row in B:
            if row[num_vars + 1] == 0 and abs(row[num_vars]) == 1:
                if row[num_vars] == -1:
                    row = -row
                if all(abs(row[i]) == 1 for i in range(num_vars)):
                    print("[+] BKZ를 통해 올바른 타겟 벡터를 찾았습니다!")
                    bits = [(row[i] + 1) // 2 for i in range(num_vars)]
                    m_int = sum([int(bits[i]) * (2**i) for i in range(num_vars)])
                    break

    if m_int is None:
        print("[-] BKZ로도 타겟 벡터를 찾지 못했습니다. 스크립트를 재실행해 주세요.")
        return

    # 간혹 선행 0(Leading Zero) 바이트가 증발하여 길이가 짧아지는 것을 방지하기 위해 pt_len으로 크기 고정
    pt_bytes = m_int.to_bytes(pt_len, 'big')
    pt_hex = pt_bytes.hex()
    
    print(f"\n[+] 🎉 복원된 평문(Hex): {pt_hex}")
    
    print("[*] 서버에 정답(Hex) 전송 중...")
    r.sendlineafter(b"pt? ", pt_hex.encode())
    
    print("[*] 최종 플래그(Flag) 확인 중...")
    try:
        result = r.recvall(timeout=3).decode()
        print("\n" + "="*50)
        print(result.strip())
        print("="*50)
    except EOFError:
        print("[-] 플래그 수신 중 연결이 끊어졌습니다.")

if __name__ == "__main__":
    solve()
