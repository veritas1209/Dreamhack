# solve_final_optimized.py
from z3 import *
from Crypto.Util.number import long_to_bytes

print("[*] Asphyxia-Hard Math-Optimized Z3 Solver")

# 1. 작은 소수들만 곱해서 P_sub 생성 (약 80비트)
# M2 < 2^64 이므로, P_sub > 2^64 이기만 하면 M2 mod P_sub == M2 가 무조건 성립합니다!
primes = [83, 271, 1459, 2273, 23398298015441]
P_sub = 1
for p in primes:
    P_sub *= p

# 2. 찐 C 배열 (GDB로 확인된 결과)
C_chunks = [
    0xa09de63b04f4601ca9418ba9dcdbd589a114e0cce80d67796ea2e0d074232e42, # Chunk 1
    0x2c9a37007879c163c481557d78124c96e9afc3016028df5ccc50b6d070d14b93, # Chunk 2
    0xec82d75b2063c72305b883caa691dff06fe0f5b972f05f07db2d15d04d98cca6, # Chunk 3
    0x40ce224b1a683ceea19c770511ca8f8c2e4b8fcbf93895af39869c8155dda2a4  # Chunk 4
]

# 파이썬 3.8 이상 내장 모듈러 역원 함수
inv2 = pow(2, -1, P_sub)

# 3. Z3를 구원할 "미리 계산된 룩업 테이블" 생성
# 각 바이트 자리(0~7)별로 0x20~0x7E 문자가 들어갔을 때의 2^(-exponent) mod P_sub 값을 미리 다 구해둡니다.
T_table = []
for i in range(8):
    row = {}
    weight = 256**(7 - i) # 빅 엔디안 가중치
    for val in range(0x20, 0x7F):
        row[val] = pow(inv2, val * weight, P_sub)
    T_table.append(row)

flag = b""

for idx, C_val in enumerate(C_chunks):
    print(f"\n[+] Processing Chunk {idx+1}...")
    s = Solver()
    
    # M1, M2의 8개 바이트를 각각 변수로 선언
    M1_bytes = [Int(f'M1_{i}_{idx}') for i in range(8)]
    M2_bytes = [Int(f'M2_{i}_{idx}') for i in range(8)]
    
    # 각 바이트는 출력 가능한 ASCII 문자
    for i in range(8):
        s.add(M1_bytes[i] >= 0x20, M1_bytes[i] <= 0x7E)
        s.add(M2_bytes[i] >= 0x20, M2_bytes[i] <= 0x7E)
        
    # M2 정수 값 조립 (빅 엔디안)
    M2_val = 0
    for i in range(8):
        M2_val = M2_val * 256 + M2_bytes[i]
        
    # Z3용 테이블 룩업 함수 (Z3 If-Else 트리 생성)
    def get_T_expr(byte_idx, byte_var):
        # 기본값을 0x20일 때로 잡고, 값에 따라 If 분기
        expr = T_table[byte_idx][0x20]
        for val in range(0x21, 0x7F):
            expr = If(byte_var == val, T_table[byte_idx][val], expr)
        return expr

    # 💥 대망의 선형 방정식: V = C * 2^(-M1) mod P_sub
    V = C_val % P_sub
    for i in range(8):
        # 거듭제곱 대신 그냥 테이블에서 값을 꺼내 곱하기만 하면 끝!
        V = (V * get_T_expr(i, M1_bytes[i])) % P_sub
        
    # 최종 검증: M2가 V와 완벽히 일치해야 함
    s.add(M2_val == V)
    
    # (옵션) 플래그 힌트: Chunk 1은 무조건 DH{ 로 시작합니다. (알고 있다면 주석 해제)
    if idx == 0:
        s.add(M1_bytes[0] == ord('D'), M1_bytes[1] == ord('H'), M1_bytes[2] == ord('{'))
    if idx == 3:
        s.add(M2_bytes[7] == ord('}'))

    if s.check() == sat:
        m = s.model()
        m1_res = bytes([m[M1_bytes[i]].as_long() for i in range(8)])
        m2_res = bytes([m[M2_bytes[i]].as_long() for i in range(8)])
        print(f"  [!] Found: {m1_res.decode()} + {m2_res.decode()}")
        flag += m1_res + m2_res
    else:
        print("  [-] Unsat! Something is wrong.")

print(f"\n[🏆] FINAL FLAG: {flag.decode()}")