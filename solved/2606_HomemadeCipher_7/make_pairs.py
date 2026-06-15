#!/usr/bin/env python3
"""
brute8 (C 전수조사기)에 넣을 충돌쌍 파일 생성.
사용: python3 make_pairs.py flag_bmp.enc pairs.txt
"""
import sys
from collections import defaultdict

enc, out = sys.argv[1], sys.argv[2]
body = open(enc, "rb").read()[54:]
SPAN, CH, MAXP = 1024, 0, 14   # 첫 1024바이트, 채널0, 가장 분리 큰 14쌍
positions = [(54 + i, body[i]) for i in range(CH, SPAN, 3)]
groups = defaultdict(list)
for p, cv in positions:
    groups[cv].append(p)
pairs = []
for ps in groups.values():
    for j in range(1, len(ps)):
        pairs.append((ps[0], ps[j]))
pairs.sort(key=lambda ab: -abs(ab[1] - ab[0]))
pairs = pairs[:MAXP]
P0 = min(p for p, _ in positions)
with open(out, "w") as f:
    f.write(f"{len(pairs)}\n{P0}\n")
    for a, b in pairs:
        f.write(f"{a} {b}\n")
print(f"{len(pairs)} pairs -> {out}")
