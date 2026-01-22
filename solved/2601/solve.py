from z3 import *
import struct

# 1. 64비트 정수 변수 4개 선언
x, y, z, w = BitVecs('x y z w', 64)

s = Solver()

# 상수값 (그대로 유지)
const_A = 0x85206c6db3f6677d
const_B = 0x07fefe3a3db63415
const_C = 0xa898cddac482c8b6
const_D = 0xf251c7aec69294bf

# 2. 수정된 연립 방정식
s.add(x + y + z + w == const_A)  # Eq 1
s.add(x + y + z     == const_B)  # Eq 2
s.add(x + y         == const_C)  # Eq 3 (수정됨: w 없음)
s.add(x     +     w == const_D)  # Eq 4 (수정됨: z 없음)

# 3. 답 구하기
if s.check() == sat:
    m = s.model()
    flag_parts = [m[x], m[y], m[z], m[w]]
    
    flag_str = b""
    for part in flag_parts:
        val = part.as_long()
        flag_str += struct.pack('<Q', val)
        
    print(f"Decoded Flag: {flag_str}")
    try:
        print(f"String View: {flag_str.decode('utf-8')}")
    except:
        pass
else:
    print("No solution found.")