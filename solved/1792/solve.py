import sys
from pwn import *
from z3 import *

# =======================================================================
# 1. 설정 및 서버 연결
# =======================================================================
HOST = 'host8.dreamhack.games'
PORT = 17212

print("[DEBUG] Exploit script started.")
print(f"[DEBUG] Target Server: {HOST}:{PORT}")
print("[DEBUG] Target PRNG: OCaml 5.x LXM (caml_lxm_next)")

context.log_level = 'debug'
r = remote(HOST, PORT)

# =======================================================================
# 2. 130개의 난수 수집
# =======================================================================
log.info("Step 1: 130개의 난수 데이터 수집 시작")
known_outputs = []

for i in range(130):
    line = r.recvline().decode().strip()
    print(f"[DEBUG] Received line {i+1}: '{line}'")
    
    parts = line.split()
    if len(parts) >= 2:
        idx = int(parts[0])
        val = int(parts[1])
        # 64비트 부호 있는 정수를 부호 없는 정수(unsigned) 형태로 맞춰줌
        if val < 0:
            val += (1 << 64)
        known_outputs.append(val)
        print(f"[DEBUG] Parsed - Index: {idx}, Unsigned Value: {val}")

print(f"[DEBUG] 총 {len(known_outputs)}개의 난수 수집 완료.")

# =======================================================================
# 3. Z3 SMT Solver를 이용한 LXM (L64X128MixRandom) 모델링
# =======================================================================
log.info("Step 2: Z3 Solver를 통한 OCaml LXM State 복구 시도")
solver = Solver()

# PRNG State: 4개의 64비트 정수 (random.ml의 set 함수 구조 반영)
print("[DEBUG] Z3 BitVec 변수 생성 중...")
s0 = BitVec('s0', 64) # i1 (LCG Addend)
s1 = BitVec('s1', 64) # i2 (LCG State)
s2 = BitVec('s2', 64) # i3 (XBG State 0)
s3 = BitVec('s3', 64) # i4 (XBG State 1)

# random.ml 제약조건: s0는 홀수여야 함 (Int64.logor i1 1L)
solver.add((s0 & 1) == 1)

current_s0 = s0
current_s1 = s1
current_s2 = s2
current_s3 = s3

def rotl(x, k):
    return RotateLeft(x, k)

# OCaml C 소스의 caml_lxm_next 상수 (표준 LXM 상수 사용)
# 주의: OCaml 버전이나 C 구현체에 따라 아래 LCG_MULTIPLIER 상수가 
# 0xd1342543de82ef95 가 아닌 2862933555777941757 등 다른 값일 수 있습니다.
LCG_MULTIPLIER = 0xd1342543de82ef95

print("[DEBUG] Z3 제약 조건(Constraints) 추가 중...")
# 130개의 제약 조건을 모두 걸면 Z3가 버거워할 수 있으므로, 
# 넉넉하게 10~15개 정도만 걸어 속도를 높입니다. (LXM의 256비트 상태는 4~5개로도 이론상 충분함)
SOLVE_LIMIT = 15 

for idx in range(SOLVE_LIMIT):
    out_val = known_outputs[idx]
    
    # 1. Mix (Lea64) - 현재 상태를 기반으로 결과값 출력
    z = current_s1 + current_s2
    z = (z ^ LShR(z, 32)) * 0xdea7139120eb3f9
    z = (z ^ LShR(z, 32)) * 0xc4ceb9fe1a85ec53
    z = z ^ LShR(z, 32)
    
    solver.add(z == out_val)
    print(f"[DEBUG] Added Constraint for index {idx}")
    
    # 2. Update LCG (Linear Congruential Generator)
    next_s1 = current_s1 * LCG_MULTIPLIER + current_s0
    
    # 3. Update XBG (Xoroshiro128)
    q0 = current_s2
    q1 = current_s3
    q1 ^= q0
    next_s2 = rotl(q0, 24) ^ q1 ^ (q1 << 16)
    next_s3 = rotl(q1, 37)
    
    # 상태 갱신
    current_s1 = next_s1
    current_s2 = next_s2
    current_s3 = next_s3

print("[DEBUG] Z3 Solver Check 실행. (수 초 ~ 수 분 소요될 수 있음)...")
if solver.check() == sat:
    log.success("PRNG 상태 복구 성공!")
    m = solver.model()
    
    # 복구된 초기 상태
    rec_s0 = m[s0].as_long()
    rec_s1 = m[s1].as_long()
    rec_s2 = m[s2].as_long()
    rec_s3 = m[s3].as_long()
    print(f"[DEBUG] Recovered Initial State: s0={hex(rec_s0)}, s1={hex(rec_s1)}, s2={hex(rec_s2)}, s3={hex(rec_s3)}")
    
    # 초기 상태부터 시작하여 서버가 소비한 130번의 상태 전이를 로컬에서 그대로 진행
    curr_0, curr_1, curr_2, curr_3 = rec_s0, rec_s1, rec_s2, rec_s3
    
    def simulate_next(c0, c1, c2, c3):
        # 파이썬에서 64비트 오버플로우 처리를 위한 마스킹
        MASK64 = 0xFFFFFFFFFFFFFFFF
        z = (c1 + c2) & MASK64
        z = (z ^ (z >> 32)) * 0xdea7139120eb3f9 & MASK64
        z = (z ^ (z >> 32)) * 0xc4ceb9fe1a85ec53 & MASK64
        z = z ^ (z >> 32)
        
        nxt_1 = (c1 * LCG_MULTIPLIER + c0) & MASK64
        q0 = c2
        q1 = c3
        q1 ^= q0
        
        def rotl_py(x, k):
            return ((x << k) & MASK64) | (x >> (64 - k))
            
        nxt_2 = (rotl_py(q0, 24) ^ q1 ^ ((q1 << 16) & MASK64))
        nxt_3 = rotl_py(q1, 37)
        
        return z, c0, nxt_1, nxt_2, nxt_3

    print("[DEBUG] 서버 상태와 동기화 (130번 진행)...")
    for _ in range(130):
        _, curr_0, curr_1, curr_2, curr_3 = simulate_next(curr_0, curr_1, curr_2, curr_3)

    # =======================================================================
    # 4. 다음 50개 난수 예측 및 전송
    # =======================================================================
    log.info("Step 3: 다음 50개의 난수 예측 및 전송")
    for i in range(50):
        pred_val, curr_0, curr_1, curr_2, curr_3 = simulate_next(curr_0, curr_1, curr_2, curr_3)
        
        # OCaml에서 출력하는 Signed 64-bit 형태로 다시 변환
        if pred_val >= (1 << 63):
            signed_pred_val = pred_val - (1 << 64)
        else:
            signed_pred_val = pred_val
            
        print(f"[DEBUG] Sending prediction {i+1}/50: {signed_pred_val} (Unsigned: {pred_val})")
        r.sendline(str(signed_pred_val).encode())
        
        response = r.recvline().decode().strip()
        print(f"[DEBUG] Server Response: {response}")
        
        if "Failed" in response:
            log.error("예측 실패! OCaml C 소스의 LXM 곱셈 상수가 다를 수 있습니다.")
            sys.exit(1)

    # =======================================================================
    # 5. 플래그 획득
    # =======================================================================
    log.info("Step 4: 플래그 대기 중...")
    try:
        flag_output = r.recvall(timeout=3).decode()
        print(f"[DEBUG] Final Server Output:\n{flag_output}")
    except EOFError:
        print("[DEBUG] Connection closed by server.")

else:
    log.error("PRNG 상태 복구 실패 (unsat).")
    log.info("[DEBUG] OCaml 버전별 C 구현체(caml_lxm_next)의 LCG 곱셈 상수나 Lea64 믹싱 상수가 다른지 확인이 필요합니다.")