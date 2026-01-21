import struct
from z3 import *

# ------------------------------------------------------------------
# 1. Data Dumps (Validated with GDB)
# ------------------------------------------------------------------
hex_574380 = """
3d c4 ae 3b d9 c8 6e cc 75 78 51 6a d1 2e 7b 06 1d 71 f2 a2 01 b9 95 3e b7 1e 33 da
18 0c cf c6 38 cd 6b 7e f0 62 07 fc c7 fc 23 de d5 98 7f c0 84 34 b7 cb 2b d0 2c 8c
c5 ec 87 9e 61 28 8a 5f fd 34 02 f0 99 1b 75 8e f5 4a a7 2a f1 5d 16 c6 25 5d b9 62
0f 00 00 00 00 00 00 00 00 00 00 00
"""
hex_5743e0 = """
e0 5e 23 f3 05 6e 02 9c f9 54 bd cb d7 ed dc f5 1c 9d b0 09 b7 9c b5 c7 9e 7e 3b 51
d7 70 93 f2 e5 e9 68 42 e5 71 30 3f bf 81 9a 2e 8c ff c0 2b 36 49 27 0c c6 30 1f fb
2e dd 51 f4 a4 60 a3 81 cf 07 26 3c 89 83 9a da 5a a5 14 07 29 d9 82 57 31 18 9f 36
12 9e e0 d0 6b 2f 8c 77 00 2d 05 f1 79 7e 24 7b 2e 39 ba 0e d5 a7 f1 bb ad ad 84 7e
e6 84 24 49 ac 23 42 76 3a 0e 62 6a 87 b6 ad f0 38 12 aa 00 3f b2 5d d9 b8 cc 5d b7
27 29 47 60 ad ab 11 95 5c 93 4a 8a 16 fd f1 c6 ff 35 58 c0 4e 5b 5f 54 ec ef be ea
d6 62 23 ee 61 3d 4c 7a 25 3a 0a 9c f6 06 ad 7b e9 b7 a3 bb b4 1c 65 07 6c b8 6f a1
fb 28 5f 82 77 f8 4c c3 97 2a ff e8 13 e4 a5 96 00 2c 9b d9 d8 72 1a eb 4d 2d 7b de
03 8f 20 35 db 50 86 0e a0 b8 16 cf a1 1c 55 b4 64 4e 53 39 0f 36 b3 e6 12 59 4c 2b
c4 8c 46 4d f5 ad 76 02 6d 55 c0 9f cb 9e 9b 2e 63 89 b2 f6 bd c3 3b 9e a4 ae 9d 22
4d db 24 f2 fb 93 39 80 e7 11 b6 dd 62 d9 72 75 97 26 68 c7
"""

def parse_bytes(h):
    return bytes.fromhex(h.replace('\n', '').replace(' ', ''))

data_direction = parse_bytes(hex_574380)
data_seed = parse_bytes(hex_5743e0)
arr_seed = struct.unpack(f'<{len(data_seed)//2}H', data_seed)

# ------------------------------------------------------------------
# 2. Logic Helpers
# ------------------------------------------------------------------
def to_ushort(x): return x & 0xFFFF
def to_short(x): return (x & 0xFFFF) - 0x10000 if (x & 0xFFFF) >= 0x8000 else (x & 0xFFFF)

def mix_nibbles(uVar10_init):
    """
    Implements the C do-while loop at 0x00406430.
    Input is (uVar24 - 1).
    """
    val = uVar10_init & 0xFF
    while True:
        uVar24 = val & 0xF      # Low Nibble
        uVar10 = (val >> 4) & 0xF # High Nibble
        
        # Inner loop runs 4 times (uVar26 from 1 to 4)
        for uVar11 in range(4):
            uVar4 = uVar24
            
            # (uVar4 >> 3 | uVar4 * 2) is 4-bit Rotate Left 1
            term1 = ((uVar4 >> 3) | (uVar4 << 1)) & 0xF
            
            term2 = (uVar11 + uVar4) & 0xFFFFFFFF
            term3 = ((uVar11 ^ 0x5D) * 3 + uVar4 * 7) & 0xFFFFFFFF
            
            xor_res = (term1 ^ term2 ^ term3) & 0xF
            uVar24 = xor_res ^ uVar10
            
            uVar10 = uVar4 # Old Low becomes High
            
        val = (uVar10 << 4) | uVar24
        if val <= 0xE0: # C: do..while(0xe0 < val) repeats if val > 0xe0
            break
    return val

def solve():
    print("[*] Initializing Z3 Solver...")
    solver = Solver()
    
    # --- Variables ---
    # pos[v] is the Grid Position (0..224) of Value v (0..224, i.e., numbers 1..225)
    pos = [Int(f'pos_{v}') for v in range(225)]
    for p in pos:
        solver.add(p >= 0, p < 225)
    solver.add(Distinct(pos))

    # dir_map[k] maps C-code Direction ID (0..5) to our Logic Move ID (0..5)
    # 0: Inner+1, 1: Inner-1, 2: Block+5, 3: Block-5, 4: Row+25, 5: Row-25
    dir_map = [Int(f'map_{k}') for k in range(6)]
    for k in range(6):
        solver.add(dir_map[k] >= 0, dir_map[k] <= 5)
    solver.add(Distinct(dir_map))
    
    # We remove the "dir_map[0]==0" assumption to handle any reordering.
    
    # --- Fixed Values Generation (Fixed Logic) ---
    print("[*] Generating Fixed Values (Corrected Input)...")
    uVar9 = 0
    iVar28 = 199
    uVar21 = 0xffffa5a5
    
    fixed_count = 0
    
    for uVar23 in range(150): # 0x96
        uVar10 = to_ushort(uVar21 ^ arr_seed[uVar23])
        
        # Scramble 1
        term = ((uVar23 >> 1) ^ ((uVar23 * 4) & 0xFF)) & 0xFF
        iVar18 = iVar28 + 0x235 + term
        cVar7 = iVar18 & 0xFF
        uVar11 = (uVar10 >> 8) & 0xFF
        
        while True:
            uVar24 = uVar11
            bVar8 = uVar24 & 0xFF
            uVar11 = (uVar24 * 0x3d + iVar18) & 0xFFFFFFFF
            iVar18 = iVar18 - 0x71
            val1 = (bVar8 << 3) | (bVar8 >> 5)
            mix = ((val1 & 0xFF) ^ (bVar8 >> 2)) & 0xFF
            uVar11 = (mix ^ uVar11 ^ uVar10) & 0xFFFFFFFF
            uVar10 = uVar24
            if (iVar18 & 0xFF) == ((cVar7 + 0x5A) & 0xFF): break
        
        uVar24_raw = uVar24 & 0xFF
        
        # --- FIX IS HERE: uVar24_raw - 1 ---
        # C Code: uVar10 = uVar24 - 1; (before mixing loop)
        mixed_val = mix_nibbles((uVar24_raw - 1) & 0xFF)
        
        # Next Seed
        s_uVar21 = to_short(uVar21)
        term_shift = to_ushort(s_uVar21 << 1)
        term_sign = 1 if s_uVar21 < 0 else 0
        uVar21 = to_ushort((term_shift | term_sign) ^ arr_seed[uVar23]) ^ uVar9
        
        # Position
        fixed_pos = to_ushort(uVar11 << 8) >> 8
        
        if fixed_pos < 225:
            # pos[Value] == Position
            solver.add(pos[mixed_val] == fixed_pos)
            fixed_count += 1
            
        iVar28 += 0x3d
        uVar9 = to_ushort(to_short(uVar9) + 0x9e37)
        
    print(f"    Applied {fixed_count} fixed constraints.")
    
    # --- Path Constraints ---
    print("[*] Generating Path Constraints...")
    
    # Pre-calculate Direction IDs for each cell
    cell_ids = [0] * 225
    for i in range(225):
        byte_idx = (i * 3) >> 3
        bit_start = (i * 3) & 7
        val = 0
        if byte_idx < len(data_direction):
            val = data_direction[byte_idx]
            if byte_idx + 1 < len(data_direction):
                val |= (data_direction[byte_idx+1] << 8)
        cell_ids[i] = (val >> bit_start) & 7

    # Z3 Function mapping Position -> MoveType
    # MoveTypeAt(p) == dir_map[ cell_ids[p] ]
    MoveTypeAt = Function('MoveTypeAt', IntSort(), IntSort())
    for i in range(225):
        d_id = cell_ids[i]
        if d_id <= 5:
            solver.add(MoveTypeAt(i) == dir_map[d_id])
        else:
            solver.add(MoveTypeAt(i) == 99) # Invalid

    for v in range(224): # For values 0 to 223 (Numbers 1 to 224)
        curr = pos[v]
        next_pos = pos[v+1]
        m_type = MoveTypeAt(curr)
        
        # Conditions for 6 possible moves
        # 0: Inner+1 (Right)  -> Next=Curr+1, Curr%5 != 4
        # 1: Inner-1 (Left)   -> Next=Curr-1, Curr%5 != 0
        # 2: Block+5 (Right)  -> Next=Curr+5, Curr%25 < 20
        # 3: Block-5 (Left)   -> Next=Curr-5, Curr%25 >= 5
        # 4: Row+25  (Down)   -> Next=Curr+25, Curr < 200
        # 5: Row-25  (Up)     -> Next=Curr-25, Curr >= 25
        
        solver.add(If(m_type == 0, And(next_pos == curr + 1, (curr % 5) != 4),
                   If(m_type == 1, And(next_pos == curr - 1, (curr % 5) != 0),
                   If(m_type == 2, And(next_pos == curr + 5, (curr % 25) < 20),
                   If(m_type == 3, And(next_pos == curr - 5, (curr % 25) >= 5),
                   If(m_type == 4, And(next_pos == curr + 25, curr < 200),
                   If(m_type == 5, And(next_pos == curr - 25, curr >= 25), False)))))))

    print("[*] Solving...")
    if solver.check() == sat:
        print("[!] SOLUTION FOUND!")
        model = solver.model()
        
        # Reconstruct Grid
        result = [0] * 225
        for v in range(225):
            idx = model[pos[v]].as_long()
            result[idx] = v + 1 # Value is 1-based
        
        out_bytes = bytes(result)
        
        # Debug Output
        print(f"    Directions Found: {[model[dir_map[k]].as_long() for k in range(6)]}")
        
        import hashlib
        print(f"    SHA256: {hashlib.sha256(out_bytes).hexdigest()}")
        
        with open('hakai_input.bin', 'wb') as f:
            f.write(out_bytes)
        print("[!] Saved 'hakai_input.bin'.")
    else:
        print("[x] UNSATISFIABLE. Please double check python version or Z3 install.")

if __name__ == "__main__":
    solve()