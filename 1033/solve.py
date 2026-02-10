from pwn import *

# 1. 설정
context.log_level = 'error'
elf_path = './multipoint2' # 바이너리 경로
elf = ELF(elf_path)

# 2. 주소 정보 (Ghidra에서 확인한 주소)
TABLE_START = 0x104050
TARGET_DATA_ADDR = 0x11ed50  # memcmp 비교 대상
TARGET_LEN = 38              # 0x26

print(f"[*] Extracting Multiplication Table from {hex(TABLE_START)}...")

# 3. 테이블 추출
# 구조: [Target(1B) | Src1(1B) | Src2(1B) | Coeff(1B)] 반복
ops = []
curr_addr = TABLE_START

while True:
    # 4바이트씩 읽기
    data = elf.read(curr_addr, 4)
    
    # 종료 조건: 4바이트가 모두 0이면 루프 끝 (코드의 while 조건)
    if data == b'\x00\x00\x00\x00':
        break
    
    # 바이트 파싱
    target = data[0]
    src1 = data[1]
    src2 = data[2]
    coeff = data[3]
    
    ops.append((target, src1, src2, coeff))
    curr_addr += 4

print(f"[+] Table loaded. Total operations: {len(ops)}")

# 4. 타겟 데이터(암호화된 플래그) 추출
target_bytes = elf.read(TARGET_DATA_ADDR, TARGET_LEN)
target_vec = list(target_bytes)
print(f"[+] Target data loaded: {target_bytes.hex()}")

# =========================================================
# 5. 수학적 복호화 (Finite Field Operation)
# =========================================================

MOD = 0xfb # 251
DIM = 38   # 0x26

# 벡터 곱셈 함수
def vec_mult(A, B):
    res = [0] * DIM
    for target, src1, src2, coeff in ops:
        # Output[target] += Input[src1] * Input[src2] * coeff
        term = (A[src1] * B[src2] * coeff) % MOD
        res[target] = (res[target] + term) % MOD
    return res

# 벡터 거듭제곱 함수 (Square and Multiply)
def vec_pow(base, exp):
    # exp 비트열 ('100...01')
    bin_exp = bin(exp)[2:] 
    
    # 초기값 설정 (base^1)
    res = list(base)
    
    for bit in bin_exp[1:]:
        # Square
        res = vec_mult(res, res)
        # Multiply
        if bit == '1':
            res = vec_mult(res, base)
    return res

# 복호화 상수 계산
# Group Order = 251^38 - 1
group_order = (MOD ** DIM) - 1
e = 65537 # (2^16 + 1)
d = pow(e, -1, group_order)

print(f"[*] Decrypting with exponent d...")

# 복호화 수행: Flag = Target^d
flag_vec = vec_pow(target_vec, d)

# 결과 출력
flag_bytes = bytes(flag_vec)
print(f"\n[SUCCESS] Flag: {flag_bytes}")

try:
    print(f"String: {flag_bytes.decode('utf-8')}")
except:
    pass