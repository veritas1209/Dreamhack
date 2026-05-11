#!/usr/bin/env sage
import sys
import hashlib
import itertools
import math
from pwn import *

# === [1] 기본 설정 ===
# TODO: 실제 대회 서버 IP와 포트로 변경하세요.
#HOST = '127.0.0.1' 
#PORT = 1337        


p = 0x273e0ccdd855bd09f6e7c6c03d5f966d0f
M = p - 1

def solve_pow(prefix, target_hash):
    log.info(f"[DEBUG] PoW 시작: SHA-256({prefix} + ???) == {target_hash}")
    # 경우의 수가 16^7 이므로 로컬 CPU 환경에 따라 1~3분 정도 소요될 수 있습니다.
    for p_tuple in itertools.product("0123456789abcdef", repeat=7):
        inp = "".join(p_tuple)
        if hashlib.sha256((prefix + inp).encode()).hexdigest() == target_hash:
            log.success(f"[DEBUG] PoW 해결 완료: {inp}")
            return inp
    log.error("[DEBUG] PoW 해결 실패")
    exit(1)

def main():
    #r = remote(HOST, PORT)
    r = process(['python3', 'chal.py'])
    
    # === [2] PoW 처리 ===
    r.recvuntil(b"SHA-256(")
    prefix = r.recvuntil(b" +", drop=True).decode()
    r.recvuntil(b"== ")
    target_hash = r.recvline().strip().decode()
    
    pow_ans = solve_pow(prefix, target_hash)
    r.sendlineafter(b"Solve PoW: ", pow_ans.encode())
    
    def query(inp_bytes):
        r.sendlineafter(b"> ", inp_bytes.hex().encode())
        res = r.recvline().strip().decode()
        if "flag" in res.lower() or "wrong" in res.lower():
            print(f"[FLAG / ERROR] {res}")
            return None
        return int(res, 16)

    # === [3] 서버 쿼리 (0^8 및 e_i) ===
    log.info("[DEBUG] 서버에 쿼리를 전송하여 65개의 Y 값들을 수집합니다.")
    Y0 = query(b'\x00' * 8)
    if Y0 is None: return
    print(f"[DEBUG] Y_0 (0^8 입력) = {hex(Y0)}")
    
    Y = []
    for i in range(64):
        inp = (1 << i).to_bytes(8, 'little')
        y_val = query(inp)
        Y.append(y_val)
        print(f"[DEBUG] Y_{i+1} (bit {i} 세팅) = {hex(y_val)}")

    # === [4] 이산 로그 (Discrete Logarithm) ===
    log.info("[DEBUG] GF(p) 상에서 이산 로그를 계산합니다. (p-1이 smooth 하므로 매우 빠름)")
    F = GF(p)
    g = F.multiplicative_generator()
    
    L0 = discrete_log(F(Y0), g)
    print(f"[DEBUG] L_0 계산 완료 = {L0}")
    
    L = []
    for i in range(64):
        l_val = discrete_log(F(Y[i]), g)
        L.append(l_val)
        print(f"[DEBUG] L_{i+1} 계산 완료 = {l_val}")

    # === [5] 격자 기저 축소 (LLL)를 통한 원본 C_i 복원 ===
    log.info("[DEBUG] LLL 알고리즘을 이용해 원래의 64-bit CRC 값(C_i)을 복원합니다.")
    C0_candidates = []
    C_i_candidates = []
    
    W = 2^128  # 마지막 열을 0으로 강제하기 위한 큰 가중치(Weight)
    
    for i in range(64):
        # L[i] * C_0 - L_0 * C_i ≡ 0 (mod M) 을 만족하는 작은 (C_0, C_i)를 찾기 위한 3x3 격자
        mat = Matrix(ZZ, [
            [1, 0, L[i] * W],
            [0, 1, -L0 * W],
            [0, 0, M * W]
        ])
        
        reduced = mat.LLL()
        
        best_v = None
        for row in reduced:
            # 마지막 열이 0이라는 것은 L[i]*x - L_0*y ≡ 0 (mod M) 방정식이 성립한다는 뜻
            if row[2] == 0 and (row[0] != 0 or row[1] != 0):
                best_v = row
                break
                
        if best_v is None:
            log.error(f"[ERROR] C_{i+1} 복원 실패")
            continue
            
        x, y = best_v[0], best_v[1]
        
        # CRC 값은 항상 양수이므로, 음수 값이 나오면 부호를 뒤집어 줌
        if x < 0:
            x, y = -x, -y
            
        C0_candidates.append(x)
        C_i_candidates.append(y)

    # gcd 이슈 방지를 위해 모든 후보의 최소공배수(LCM)로 정확한 C0 도출
    C0 = 1
    for x in C0_candidates:
        if x != 0:
            C0 = math.lcm(C0, int(x))
            
    C = [C0]
    for i in range(64):
        x = int(C0_candidates[i])
        y = int(C_i_candidates[i])
        if x != 0:
            C.append(y * (C0 // x))
        else:
            C.append(0)

    print(f"[DEBUG] 완벽 복원된 C_0 = {hex(C[0])}")
    for i in range(64):
        print(f"[DEBUG] 복원된 C_{i+1} = {hex(C[i+1])}")

    # === [6] GF(2) 선형 대수 행렬 풀이 ===
    log.info("[DEBUG] GF(2) 상에서 CRC = 0 이 되는 해를 구합니다.")
    import operator # SageMath의 ^ (제곱) 변환 우회를 위해 추가
    
    M_mat = Matrix(GF(2), 64, 64)
    for i in range(64):
        # ^ 대신 operator.xor()를 사용하여 안전하게 비트 XOR 수행
        col_val = operator.xor(int(C[i+1]), int(C[0]))
        for j in range(64):
            M_mat[j, i] = (col_val >> j) & 1

    target = int(C[0])
    target_bits = vector(GF(2), [(target >> j) & 1 for j in range(64)])

    try:
        x_bits = M_mat.solve_right(target_bits)
    except ValueError:
        log.error("[ERROR] M_mat 역행렬이 존재하지 않습니다!")
        return

    ans_int = 0
    for j in range(64):
        ans_int |= (int(x_bits[j]) << j)
        
    ans_bytes = ans_int.to_bytes(8, 'little')
    print(f"[DEBUG] 최종 계산된 Payload (CRC가 0이 되는 값): {ans_bytes.hex()}")

if __name__ == '__main__':
    main()