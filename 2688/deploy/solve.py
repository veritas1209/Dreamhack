import struct

def rol(val, n):
    n = n % 64
    return ((val << n) | (val >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

def ror(val, n):
    n = n % 64
    return ((val >> n) | (val << (64 - n))) & 0xFFFFFFFFFFFFFFFF

def modinv(a, m):
    return pow(a, -1, m)

# ==========================================
# 1. 확정된 상수 (From Ghidra & GDB)
# ==========================================
# GDB에서 구한 "Input=0"일 때의 결과값 (필수!)
REAL_VAL_0 = 0x12e10926bdda5dc0

# Ghidra에서 확인된 Keys
K_ADD1 = 0x0123456789abcdef
K_ROL  = 5
K_MUL  = 0x13               # Trace A & Ghidra 일치
K_ADD2 = 0x0a0a0a0a0a0a0a0a # Ghidra "0xa0a0a0a" -> 64bit 확장
K_XOR  = 0x0f0f0f0f0f0f0f0f # Ghidra "0xf0f0f0f" -> 64bit 확장

# ==========================================
# 2. 파이프라인 순서 찾기 (Logic Matcher)
# ==========================================
# 가능한 시나리오:
# 1. NOT -> ADD2 -> XOR
# 2. NOT -> XOR -> ADD2
# (기드라에 NOT이 있었으므로 NOT은 필수 포함)

print("[*] Verifying logic pipeline...")

# Start Value (Input 0 -> Phase 1 -> Phase 2 MUL)
val_start = (0 + K_ADD1) & 0xFFFFFFFFFFFFFFFF
val_start = rol(val_start, K_ROL)
val_after_mul = (val_start * K_MUL) & 0xFFFFFFFFFFFFFFFF

correct_order = None

# Case 1: NOT -> ADD -> XOR
# 식: ((~Mul) + ADD2) ^ XOR
temp = (~val_after_mul) & 0xFFFFFFFFFFFFFFFF
res1 = ((temp + K_ADD2) & 0xFFFFFFFFFFFFFFFF) ^ K_XOR

if res1 == REAL_VAL_0:
    print("[!] LOGIC CONFIRMED: NOT -> ADD -> XOR")
    correct_order = 1

# Case 2: NOT -> XOR -> ADD
# 식: ((~Mul) ^ XOR) + ADD2
temp = (~val_after_mul) & 0xFFFFFFFFFFFFFFFF
res2 = ((temp ^ K_XOR) + K_ADD2) & 0xFFFFFFFFFFFFFFFF

if res2 == REAL_VAL_0:
    print("[!] LOGIC CONFIRMED: NOT -> XOR -> ADD")
    correct_order = 2

# 만약 둘 다 아니라면, K_ADD2가 0xa0a0... 일 수도 있음 (리틀엔디안 해석 차이)
if not correct_order:
    print("[-] Standard logic failed. Checking ADD2 Padding variant (0xa0...)")
    K_ADD2 = 0xa0a0a0a0a0a0a0a0
    # Re-test Case 1
    temp = (~val_after_mul) & 0xFFFFFFFFFFFFFFFF
    res1 = ((temp + K_ADD2) & 0xFFFFFFFFFFFFFFFF) ^ K_XOR
    if res1 == REAL_VAL_0:
        print("[!] LOGIC CONFIRMED: NOT -> ADD -> XOR (with 0xa0 padding)")
        correct_order = 1
    
if not correct_order:
    print("[-] Critical Failure: Pipeline assumes standard ADD/XOR/NOT ops.")
    # 그래도 진행합니다 (Case 1이 가장 유력)
    correct_order = 1 
    K_ADD2 = 0x0a0a0a0a0a0a0a0a # Reset

# ==========================================
# 3. 전체 복호화 (Full Decryption)
# ==========================================
print("\n[*] Decrypting Flag...")

# Keys Setup
add_keys_1 = [
    0x0123456789abcdef, 0x0f0e0d0c0b0a0908, 0x1111111111111111, 0x2222222222222222,
    0x3333333333333333, 0x4444444444444444, 0x5555555555555555, 0x6666666666666666
]
rol_keys = [5, 11, 17, 23, 29, 3, 7, 13]
mul_keys = [0x13 + (i*2) for i in range(8)]
add_keys_2 = [
    0x0a0a0a0a0a0a0a0a, 0x1b1b1b1b1b1b1b1b, 0x2c2c2c2c2c2c2c2c, 0x3d3d3d3d3d3d3d3d,
    0x4e4e4e4e4e4e4e4e, 0x5f5f5f5f5f5f5f5f, 0x6060606060606060, 0x7171717171717171
]
xor_keys = [
    0x0f0f0f0f0f0f0f0f, 0xf0f0f0f0f0f0f0f0, 0xaaaaaaaa55555555, 0x55555555aaaaaaaa,
    0x1234567890abcdef, 0xfedcba9876543210, 0x0f1e2d3c4b5a6978, 0x89abcdef01234567
]

# Fix Padding for Block 0 (Based on Logic Search)
if K_ADD2 == 0xa0a0a0a0a0a0a0a0:
    add_keys_2[0] = 0xa0a0a0a0a0a0a0a0

# Fix Padding for XOR (Trace B data seems reliable for others, but Block 0/6 might need fix)
# Ghidra says 0x0f0f... for Block 0. Trace B says 0x0f0f... Trust Trace B/Ghidra overlap.
xor_keys[0] = 0x0f0f0f0f0f0f0f0f
xor_keys[6] = 0x0f1e2d3c4b5a6978

flag_bytes = b""

for i in range(8):
    # Target is the value compared against (== ADD2 Key)
    val = add_keys_2[i]
    
    # 1. Reverse Phase 3 & 2 (Check Loop + NOT)
    if correct_order == 1:
        # Forward: ((~M) + ADD2) ^ XOR = Target
        # Reverse: ~M = (Target ^ XOR) - ADD2
        val = val ^ xor_keys[i]
        val = (val - add_keys_2[i]) & 0xFFFFFFFFFFFFFFFF
        val = (~val) & 0xFFFFFFFFFFFFFFFF
    else:
        # Forward: ((~M) ^ XOR) + ADD2 = Target
        # Reverse: ~M = (Target - ADD2) ^ XOR
        val = (val - add_keys_2[i]) & 0xFFFFFFFFFFFFFFFF
        val = val ^ xor_keys[i]
        val = (~val) & 0xFFFFFFFFFFFFFFFF
        
    # 2. Reverse Phase 2 (MUL)
    try:
        m_inv = modinv(mul_keys[i], 2**64)
        val = (val * m_inv) & 0xFFFFFFFFFFFFFFFF
    except:
        print(f"[-] Error: MUL key {hex(mul_keys[i])} not invertible.")
        continue
        
    # 3. Reverse Phase 1 (ROL -> ADD1)
    val = ror(val, rol_keys[i])
    val = (val - add_keys_1[i]) & 0xFFFFFFFFFFFFFFFF
    
    flag_bytes += struct.pack("<Q", val)

print("\n" + "="*40)
print("Final Flag Result:")
print("="*40)
print(flag_bytes)
try:
    print(flag_bytes.decode('utf-8'))
except:
    pass