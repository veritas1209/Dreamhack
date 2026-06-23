#!/usr/bin/env python3
# 모든 bin_0..bin_(N-1) 복원 -> 7바이트씩 이어붙여 flag.png 생성.
# 사용: python3 assemble_flag.py <bins_dir> [count] [out.png]
import sys, os
from decode_bin import recover, decode8to7, valid
d = sys.argv[1]; n = int(sys.argv[2]) if len(sys.argv)>2 else 995
out = sys.argv[3] if len(sys.argv)>3 else "flag_real.png"
data = bytearray(); bad = []
for i in range(n):
    p = os.path.join(d, f"bin_{i}")
    if not os.path.exists(p): p += ".elf"
    key, exp, a8 = recover(p)
    if not valid(a8): bad.append(i)
    try: data += decode8to7(a8)
    except Exception: data += b'\x00'*7; bad.append(i)
data = bytes(data[:6963])
open(out,'wb').write(data)
print(f"wrote {out} ({len(data)} bytes); invalid/FAKE chunks: {len(bad)} {bad[:20]}")
print("PNG magic OK" if data[:8]==bytes.fromhex('89504e470d0a1a0a') else "PNG magic MISSING (아직 디코이/미패치)")
