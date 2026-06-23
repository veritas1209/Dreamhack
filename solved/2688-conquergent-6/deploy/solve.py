from z3 import *
import struct

# -----------------------------------------------------------------------------
# 1. Helper Functions
# -----------------------------------------------------------------------------
def u64_concat(low_s32, high_s32):
    l = struct.unpack("<I", struct.pack("<i", low_s32))[0]
    h = struct.unpack("<I", struct.pack("<i", high_s32))[0]
    return (h << 32) | l

def ROL64(x, n): return RotateLeft(x, n)
def ROR64(x, n): return RotateRight(x, n)

# -----------------------------------------------------------------------------
# 2. Key Data Preparation
# -----------------------------------------------------------------------------

# [Loop K Keys]
add_keys = [
    0x0123456789ABCDEF, 0x0F0E0D0C0B0A0908, 0x1111111111111111, 0x2222222222222222,
    0x3333333333333333, 0x4444444444444444, 0x5555555555555555, 0x6666666666666666
]

v24 = -2023406815
raw_v25 = [-19088887, 19088743, -1985229329, -559038737, -889275714, -559038242, 195948557, 610839776, 324508639, 305419896, -889259314, 252645135, 252645135, -252645136, -252645136, 0]
xor_keys_k = []
xor_keys_k.append(u64_concat(v24, raw_v25[0]))
for i in range(1, 8):
    xor_keys_k.append(u64_concat(raw_v25[2*i - 1], raw_v25[2*i]))

rol_shifts = [5, 11, 17, 23, 29, 3, 7, 13]
mul_keys_k = [19, 21, 23, 25, 27, 29, 31, 33]

# [Loop N Keys]
str_v23 = b",,,,,,,,========NNNNNNNN________````````qqqqqqqq"
v23_ints = [struct.unpack("<i", str_v23[i:i+4])[0] for i in range(0, 48, 4)]
raw_v22 = [168430090, 168430090, 454761243, 454761243] + v23_ints
add_keys_n = [u64_concat(raw_v22[2*i], raw_v22[2*i+1]) for i in range(8)]

ror_shifts = [8, 16, 24, 32, 4, 12, 20, 28]

raw_v14 = [252645135, 252645135, -252645136, -252645136, 1431655765, -1431655766, -1431655766, 1431655765, -1867788817, 305419896, 1985229328, -19088744, 1264216440, 253635900, 19088743, -1985229329]
xor_keys_n = [u64_concat(raw_v14[2*i], raw_v14[2*i+1]) for i in range(8)]

mul_keys_n = [49, 51, 53, 55, 57, 59, 61, 63]

raw_v15 = [168430090, 168430090, 454761243, 454761243] + v23_ints
sub_keys_n = [u64_concat(raw_v15[2*i], raw_v15[2*i+1]) for i in range(8)]

# [Final Targets]
raw_cmp1 = [-440984412, 904793942, 1779455741, 1073561761, 744203034, -900566299, -1834542299, 1807946251, -1028049501, 273666806, 1672589782, -239744458, -623728120, -891090128, -1052938562, 1971764109]
targets = [u64_concat(raw_cmp1[2*i], raw_cmp1[2*i+1]) for i in range(8)]

# -----------------------------------------------------------------------------
# 3. Z3 Logic
# -----------------------------------------------------------------------------
s = Solver()
flag = [BitVec(f'f_{i}', 64) for i in range(8)]

# Step 1: Simulate Loop K (1st Transform)
intermediate = []
for k in range(8):
    x = flag[k]
    x = x + add_keys[k]
    x = x ^ xor_keys_k[k]
    x = ROL64(x, rol_shifts[k])
    x = x * mul_keys_k[k]
    x = -x # NEG
    intermediate.append(x)

# Step 2: Simulate Loop M (Bitwise Mixing)
# New Q0 = (Q0 & AA..) | (Q1 & 55..)
# New Q1 = (Q1 & AA..) | (Q0 & 55..)
MASK_AA = 0xAAAAAAAAAAAAAAAA
MASK_55 = 0x5555555555555555
mixed = [None] * 8

for m in range(0, 8, 2):
    q0 = intermediate[m]
    q1 = intermediate[m+1]
    
    mixed[m]   = (q0 & MASK_AA) | (q1 & MASK_55)
    mixed[m+1] = (q1 & MASK_AA) | (q0 & MASK_55)

# Step 3: Simulate Loop N (2nd Transform)
for n in range(8):
    x = mixed[n]
    
    x = x + add_keys_n[n]
    # Skipped DIV/MOD NOP
    x = ROR64(x, ror_shifts[n])
    x = x ^ xor_keys_n[n]
    x = x * mul_keys_n[n]
    x = x - sub_keys_n[n]
    
    # Final Constraint
    s.add(x == targets[n])

# Optional: ASCII Constraint
for i in range(8):
    for b in range(0, 64, 8):
        byte_val = Extract(b+7, b, flag[i])
        s.add(byte_val >= 0x20)
        s.add(byte_val <= 0x7E)

# -----------------------------------------------------------------------------
# 4. Solve
# -----------------------------------------------------------------------------
print("[*] Running Solver...")
if s.check() == sat:
    m = s.model()
    result = b""
    for i in range(8):
        val = m[flag[i]].as_long()
        result += struct.pack("<Q", val)
    print(f"\n[+] FLAG FOUND: {result.decode(errors='ignore')}")
else:
    print("[-] UNSAT")