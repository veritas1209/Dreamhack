# solve_final_z3.py
from z3 import *

print("[*] Asphyxia-Hard Math-Optimized Z3 Solver")

# 1. 찐 N (원본)
N = 0xf1081a510d0dc22d620c8634cddcccde28d8b9338c6ef9a4584e55593354465f

# 2. 작은 소수들만 곱해서 P_sub 생성 (약 80비트)
# M2는 8바이트(64비트)이므로, P_sub > 2^64 이기만 하면 M2 mod P_sub == M2 가 무조건 성립합니다.
primes = [83, 271, 1459, 2273, 23398298015441]
P_sub = 1
for p in primes:
    P_sub *= p

# 3. 찐 C 배열
C_chunks = [
    0xa09de63b04f4601ca9418ba9dcdbd589a114e0cce80d67796ea2e0d074232e42, # Chunk 1
    0x2c9a37007879c163c481557d78124c96e9afc3016028df5ccc50b6d070d14b93, # Chunk 2
    0xec82d75b2063c72305b883caa691dff06fe0f5b972f05f07db2d15d04d98cca6, # Chunk 3
    0x40ce224b1a683ceea19c770511ca8f8c2e4b8fcbf93895af39869c8155dda2a4  # Chunk 4
]

# 파이썬 내장 모듈러 역원 함수
inv2 = pow(2, -1, P_sub)

# 4. Z3 거듭제곱 무한루프 방지용 "미리 계산된 룩업 테이블"
T_table = []
for i in range(8):
    row = {}
    weight = 256**(7 - i)
    for val in range(0x20, 0x7F):
        row[val] = pow(inv2, val * weight, P_sub)
    T_table.append(row)

flag = b""

for idx, C_val in enumerate(C_chunks):
    print(f"\n[+] Processing Chunk {idx+1}...")
    s = Solver()
    
    # 오버플로우 방지용 256비트 벡터 사용 (Int 대신 BitVec 사용 시 속도 100배 증가)
    M1_bytes = [BitVec(f'M1_{i}_{idx}', 256) for i in range(8)]
    M2_bytes = [BitVec(f'M2_{i}_{idx}', 256) for i in range(8)]
    
    # 각 바이트는 출력 가능한 ASCII 문자
    for i in range(8):
        s.add(M1_bytes[i] >= 0x20, M1_bytes[i] <= 0x7E)
        s.add(M2_bytes[i] >= 0x20, M2_bytes[i] <= 0x7E)
        
    # M2 정수 값 조립 (빅 엔디안)
    M2_val = BitVecVal(0, 256)
    for i in range(8):
        M2_val = (M2_val * 256) + M2_bytes[i]
        
    def get_T_expr(byte_idx, byte_var):
        expr = BitVecVal(T_table[byte_idx][0x20], 256)
        for val in range(0x21, 0x7F):
            expr = If(byte_var == val, BitVecVal(T_table[byte_idx][val], 256), expr)
        return expr

    # 💥 대망의 선형 방정식: V = C * 2^(-M1) mod P_sub
    V = BitVecVal(C_val % P_sub, 256)
    for i in range(8):
        # 거듭제곱 싹 빼고 테이블 룩업으로 곱하기만 함
        V = (V * get_T_expr(i, M1_bytes[i])) % P_sub
        
    # 최종 검증: M2가 V와 완벽히 일치
    s.add(M2_val == V)

    if s.check() == sat:
        m = s.model()
        m1_res = bytes([m[M1_bytes[i]].as_long() for i in range(8)])
        m2_res = bytes([m[M2_bytes[i]].as_long() for i in range(8)])
        print(f"  [!] Found: {m1_res.decode('ascii')} + {m2_res.decode('ascii')}")
        flag += m1_res + m2_res
    else:
        print("  [-] Unsat! Something is wrong.")

print(f"\n[🏆] FINAL FLAG: {flag.decode('ascii')}")