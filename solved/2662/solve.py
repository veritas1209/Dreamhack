import struct

def ror(val, r_bits, max_bits=32):
    return ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
           (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def rol(val, r_bits, max_bits=32):
    return (val << (r_bits%max_bits) & (2**max_bits-1)) | \
           ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# 1. Constants
dat_e0 = [0x4E3D5B57, 0xFA3D63D1, 0x211EE71C, 0xFB413304]
dat_d0 = [0x37389135, 0xD79003AF, 0xEABB1122, 0x210FFBAC]

# 2. Key & Target Generation
key1 = [0] * 4
targets = [0] * 4

iVar9 = 0x11111111
bVar5 = 3

for i in range(4):
    # Key1 (local_78)
    val = (dat_e0[i] - iVar9) & 0xFFFFFFFF
    rot = bVar5 & 0x1f
    res = ror(val, rot) ^ 0xa5a5a5a5
    key1[i] = res
    
    # Targets (local_68)
    val = (dat_d0[i] - iVar9) & 0xFFFFFFFF
    # iVar9 update happens in between in the C code:
    # "uVar2 = *(&DAT_e0 + lVar7) - iVar9; ... *(&local_78 + lVar7) = ..."
    # "uVar2 = *(&DAT_d0 + lVar7) - iVar9; iVar9 += 0x11111111; ..."
    # The subtract for d0 uses the OLD iVar9.
    
    rot = (bVar5 & 0x1f) # bVar5 is updated after this use for the next part?
    # Code: bVar13 = bVar5 & 0x1f; bVar5 += 7;
    # Then shift uses bVar13. 
    # So both e0 and d0 use the same rotation count.
    
    res = ror(val, rot) ^ 0xa5a5a5a5
    targets[i] = res
    
    # Updates for next iteration
    iVar9 = (iVar9 + 0x11111111) & 0xFFFFFFFF
    bVar5 += 7

# Key2 is Key1 reversed
key2 = key1[::-1]

print(f"Key1: {[hex(x) for x in key1]}")
print(f"Key2: {[hex(x) for x in key2]}")
print(f"Targets: {[hex(x) for x in targets]}")

# 3. Decrypt Block 1 (XTEA)
v0, v1 = targets[0], targets[1]
delta = 0x9e3779b9
sum_val = (delta * 32) & 0xFFFFFFFF # 0xC6EF3720

for _ in range(32):
    v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + key1[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
    sum_val = (sum_val - delta) & 0xFFFFFFFF
    v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + key1[sum_val & 3]))) & 0xFFFFFFFF

block1 = struct.pack("<II", v0, v1)

# 4. Decrypt Block 2 (Custom)
v0, v1 = targets[2], targets[3]
# Initial IV for Block 2 is Key1[3] due to stack overlap
iv_val = key1[3] 
delta = 0x7f4a7c15

# Pre-calculate IVs for each round (running forward logic)
ivs = []
curr_iv = iv_val
sum_val = 0
for _ in range(32):
    # The loop uses (local_6c + sum)
    term = (curr_iv + sum_val) & 0xFFFFFFFF
    ivs.append(term)
    
    sum_val = (sum_val + delta) & 0xFFFFFFFF
    curr_iv = key2[sum_val & 3]

# Decrypt backwards
sum_val = (delta * 32) & 0xFFFFFFFF # 0xE94F82A0
for i in range(31, -1, -1):
    # In forward: 
    # 1. v0 += ... ^ (local_6c + sum_old)
    # 2. v1 += ... (uses v0_new)
    # 3. Check sum == end
    # 4. Update local_6c
    
    # Reverse:
    # 1. v1 -= ...
    # 2. v0 -= ... ^ ivs[i]
    
    # Forward loop sum update: sum += delta.
    # So at step i (0-indexed), sum was (i * delta).
    # ivs[i] stores (local_6c + sum_old).
    
    current_sum_for_round = (i * delta) & 0xFFFFFFFF
    next_sum = (current_sum_for_round + delta) & 0xFFFFFFFF
    
    # Decrypt v1
    # v1 += ((v0 * 16 ^ v0 >> 5) + v0 ^ key2[next_sum >> 11 & 3] + next_sum)
    term = (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (key2[(next_sum >> 11) & 3] + next_sum)
    v1 = (v1 - term) & 0xFFFFFFFF
    
    # Decrypt v0
    # v0 += ((v1 * 16 ^ v1 >> 5) + v1 ^ uVar6)
    # uVar6 was ivs[i]
    term = (((v1 << 4) ^ (v1 >> 5)) + v1) ^ ivs[i]
    v0 = (v0 - term) & 0xFFFFFFFF

block2 = struct.pack("<II", v0, v1)
decrypted_data = list(block1 + block2)

# 5. Reverse Transformation
# Forward:
# bVar5 = 0; bVar13 = 0xa5;
# loop 16:
#   shift = ...
#   bVar14 = input ^ bVar13
#   output = (bVar5 ^ 0x3d) + ROL(bVar14, shift)
#   bVar13 += 0xb
#   bVar5 += 7

flag = []
bVar5 = 0
bVar13 = 0xa5

for i in range(16):
    val = decrypted_data[i]
    
    # Reverse add
    # output = offset + rotated
    offset = (bVar5 ^ 0x3d) & 0xFF
    rotated = (val - offset) & 0xFF
    
    # Reverse Rotation
    # shift calc
    # iVar9 = (int)(uVar12 * 0x24924925 >> 0x20); ... 
    # Logic: shift = (i % 7) + 1  <-- Simplified based on commonly seen constants like 0x24924925 (1/7)
    # Let's verify: (i * 0x24924925) >> 32 is i/7. 
    # bVar1 = i + (i/7)*-7 + 1 = i % 7 + 1. Correct.
    shift = (i % 7) + 1
    
    # ROL(x, s) -> ROR(y, s)
    bVar14 = ror(rotated, shift, 8)
    
    # Reverse XOR
    original = bVar14 ^ bVar13
    flag.append(original)
    
    bVar13 = (bVar13 + 0xb) & 0xFF
    bVar5 += 7

print("Flag:", bytes(flag).decode('utf-8', 'ignore'))