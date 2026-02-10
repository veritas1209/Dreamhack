import struct
import itertools

# ==========================================
# 1. Constants (확실한 팩트)
# ==========================================
REAL_VAL_0 = 0x12e10926bdda5dc0
K_ROL = 5
K_MUL = 0x13  # Trace Memory로 확인됨

# ==========================================
# 2. Key Part Candidates (Ghidra Raw Data)
# ==========================================
# ADD1 parts
ADD1_HI = 0x01234567
ADD1_LO = 0x89abcdef

# ADD2 parts (0x0a0a0a0a repeated)
ADD2_HI = 0x0a0a0a0a
ADD2_LO = 0x0a0a0a0a

# XOR parts (0x0f0f0f0f repeated)
XOR_HI = 0x0f0f0f0f
XOR_LO = 0x0f0f0f0f

# ==========================================
# 3. Solvers
# ==========================================
def rol(val, n):
    n = n % 64
    return ((val << n) | (val >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

def ror(val, n):
    n = n % 64
    return ((val >> n) | (val << (64 - n))) & 0xFFFFFFFFFFFFFFFF

def egcd(a, b):
    if a == 0: return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1: raise Exception('modular inverse does not exist')
    else: return x % m

def solve_linear_congruence(A, B):
    # A * x = B mod 2^64
    if A == 0: return None
    tz = 0
    while (A & 1) == 0:
        A >>= 1
        tz += 1
    
    if (B & ((1 << tz) - 1)) != 0:
        return None # No solution (Parity mismatch)
    
    B >>= tz
    modulus = 1 << (64 - tz)
    try:
        inv = modinv(A, modulus)
        return (B * inv) & (modulus - 1)
    except:
        return None

# ==========================================
# 4. The Grand Search
# ==========================================
print("[*] Re:Zero - Brute forcing Key Endianness & Logic...")

# 키 조합 생성 함수
def get_key_variants(hi, lo):
    # Case 1: Standard Little Endian (LO | HI<<32)
    # Case 2: Swapped / Big Endian (HI | LO<<32)
    k1 = (hi << 32) | lo
    k2 = (lo << 32) | hi
    return list(set([k1, k2])) # remove duplicates if symmetric

cand_add1 = get_key_variants(ADD1_HI, ADD1_LO)
cand_add2 = get_key_variants(ADD2_HI, ADD2_LO) # Might include 0xa0a0...
cand_xor  = get_key_variants(XOR_HI, XOR_LO)

found_config = None

for k_add1 in cand_add1:
    # Calculate Base_In once per ADD1 candidate
    # Input(0) -> ADD1 -> ROL
    base_in = rol((0 + k_add1) & 0xFFFFFFFFFFFFFFFF, K_ROL)
    
    for k_add2 in cand_add2:
        for k_xor in cand_xor:
            for order in ["ADD_THEN_XOR", "XOR_THEN_ADD"]:
                for has_not in [True]: # Trace showed NOT is present
                    
                    # Reverse Logic Phase
                    val = REAL_VAL_0
                    if order == "ADD_THEN_XOR":
                        val = val ^ k_xor
                        val = (val - k_add2) & 0xFFFFFFFFFFFFFFFF
                    else:
                        val = (val - k_add2) & 0xFFFFFFFFFFFFFFFF
                        val = val ^ k_xor
                        
                    if has_not:
                        val = (~val) & 0xFFFFFFFFFFFFFFFF
                        
                    target_out = val
                    
                    # Check if M=0x13 fits
                    # base_in * 0x13 == target_out ?
                    if (base_in * K_MUL) & 0xFFFFFFFFFFFFFFFF == target_out:
                        print(f"[!] FOUND CONFIGURATION!")
                        print(f"    ADD1: {hex(k_add1)}")
                        print(f"    ADD2: {hex(k_add2)}")
                        print(f"    XOR : {hex(k_xor)}")
                        print(f"    Order: {order}")
                        found_config = {
                            'ADD1': k_add1, 'ADD2': k_add2, 'XOR': k_xor,
                            'ORDER': order, 'NOT': True
                        }
                        break
                if found_config: break
            if found_config: break
        if found_config: break
    if found_config: break

if not found_config:
    print("[-] Still failed. Check constants: REAL_VAL_0, K_ROL, K_MUL.")
    # Fallback: maybe ROL happens AFTER MUL? 
    # But Trace said ROL then MUL. Trust the Trace.
    exit()

# ==========================================
# 5. Decrypt
# ==========================================
print("[*] Decrypting with found config...")

# Generate Full Keys based on the found Endianness pattern
# We assume the Endianness logic found for Block 0 applies to ALL blocks.

# Raw Data Arrays (Hi/Lo parts from Ghidra/Trace)
# ADD1
raw_add1_hi = [0x01234567, 0x0f0e0d0c, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666]
raw_add1_lo = [0x89abcdef, 0x0b0a0908, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666]

# ADD2 (0x0a... pattern)
raw_add2_part = 0x0a0a0a0a
if found_config['ADD2'] == 0xa0a0a0a0a0a0a0a0:
    # Detect padding variant
    raw_add2_part = 0xa0a0a0a0 

# XOR (0x0f... pattern) - Trace B suggests consistent pattern except start/end?
# Let's construct based on Trace B values but apply Endian swap if detected
# Trace B XORs: f0f0..., f0f0..., aaaa..., 5555...
xor_keys_trace = [
    0x0f0f0f0f0f0f0f0f, 0xf0f0f0f0f0f0f0f0, 0xaaaaaaaa55555555, 0x55555555aaaaaaaa,
    0x1234567890abcdef, 0xfedcba9876543210, 0x0f1e2d3c4b5a6978, 0x89abcdef01234567
]

# Check if we need to swap halves of Trace B keys
# If found_config XOR is swapped relative to 0x0f0f0f0f0f0f0f0f, we swap all.
# 0x0f0f... is symmetric, so we can't tell from Block 0 XOR key alone unless it was 0xf0...
# We rely on ADD1 swap detection which is the strongest indicator.

swap_halves = False
if found_config['ADD1'] == (raw_add1_lo[0] << 32) | raw_add1_hi[0]:
    print("[*] Detected SWAPPED Key Endianness (LO | HI<<32)")
    swap_halves = True
else:
    print("[*] Detected Standard Key Endianness (HI | LO<<32) ... Wait, Standard is LO | HI<<32?")
    # Let's just use the logic:
    # constructed = (HI << 32) | LO  (This is what we tried as k1)
    pass

final_add1 = []
for h, l in zip(raw_add1_hi, raw_add1_lo):
    if swap_halves: final_add1.append((l << 32) | h)
    else: final_add1.append((h << 32) | l)

final_add2 = [found_config['ADD2']] * 8 # Apply found ADD2 to all

final_xor = []
for k in xor_keys_trace:
    if swap_halves:
        # Swap 32-bit halves
        final_xor.append( ((k & 0xFFFFFFFF) << 32) | (k >> 32) )
    else:
        final_xor.append(k)
# Override Block 0 XOR with confirmed one just in case
final_xor[0] = found_config['XOR']


# Execution
rol_keys = [5, 11, 17, 23, 29, 3, 7, 13]
mul_keys = [0x13 + (i*2) for i in range(8)]

flag_bytes = b""
for i in range(8):
    val = final_add2[i] # Target
    
    # Reverse Logic
    if found_config['ORDER'] == "ADD_THEN_XOR":
        val = val ^ final_xor[i]
        val = (val - final_add2[i]) & 0xFFFFFFFFFFFFFFFF
    else:
        val = (val - final_add2[i]) & 0xFFFFFFFFFFFFFFFF
        val = val ^ final_xor[i]
    
    if found_config['NOT']:
        val = (~val) & 0xFFFFFFFFFFFFFFFF
        
    val = (val * modinv(mul_keys[i], 2**64)) & 0xFFFFFFFFFFFFFFFF
    
    val = ror(val, rol_keys[i])
    val = (val - final_add1[i]) & 0xFFFFFFFFFFFFFFFF
    
    flag_bytes += struct.pack("<Q", val)

print("\n" + "="*40)
print(flag_bytes)
try: print(flag_bytes.decode('utf-8'))
except: pass