from pwn import *

# 1. 설정
context.log_level = 'error'
elf_path = './multipoint2'
try:
    elf = ELF(elf_path)
except:
    print(f"[-] 파일을 찾을 수 없습니다: {elf_path}")
    exit()

# =========================================================
# [중요] 주소 보정 (Ghidra Addr -> File Offset)
# Ghidra Base Address: 0x100000
# =========================================================
ghidra_base = 0x100000

# Ghidra에서 본 주소
table_vaddr = 0x104050
target_vaddr = 0x11ed50

# 실제 파일 오프셋 계산
TABLE_OFFSET = table_vaddr - ghidra_base
TARGET_OFFSET = target_vaddr - ghidra_base
TARGET_LEN = 38

print(f"[*] Extracting Table from File Offset: {hex(TABLE_OFFSET)}")

# 3. 테이블 추출
ops = []
curr_offset = TABLE_OFFSET

while True:
    # 파일 오프셋으로 읽기
    try:
        data = elf.read(curr_offset, 4)
    except:
        break # 파일 끝 도달 시
    
    # 종료 조건 (00 00 00 00)
    if data == b'\x00\x00\x00\x00':
        break
    
    ops.append((data[0], data[1], data[2], data[3]))
    curr_offset += 4

print(f"[+] Table loaded. Total operations: {len(ops)}")

# 4. 타겟 데이터 추출
print(f"[*] Extracting Target from File Offset: {hex(TARGET_OFFSET)}")
target_bytes = elf.read(TARGET_OFFSET, TARGET_LEN)
target_vec = list(target_bytes)

# =========================================================
# 5. 수학적 복호화
# =========================================================

MOD = 0xfb # 251
DIM = 38   # 0x26

def vec_mult(A, B):
    res = [0] * DIM
    for target, src1, src2, coeff in ops:
        term = (A[src1] * B[src2] * coeff) % MOD
        res[target] = (res[target] + term) % MOD
    return res

def vec_pow(base, exp):
    bin_exp = bin(exp)[2:] 
    res = list(base)
    for bit in bin_exp[1:]:
        res = vec_mult(res, res)
        if bit == '1':
            res = vec_mult(res, base)
    return res

# 복호화
group_order = (MOD ** DIM) - 1
e = 65537
d = pow(e, -1, group_order)

print(f"[*] Decrypting...")
flag_vec = vec_pow(target_vec, d)
flag_bytes = bytes(flag_vec)

print(f"\n[SUCCESS] Flag: {flag_bytes}")
try:
    print(f"String: {flag_bytes.decode('utf-8')}")
except:
    pass