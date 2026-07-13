#!/usr/bin/env python3
"""Quick correctness check: verifies the embedded block-1 cipher and decrypts
block 1 of hello_png.enc, which must yield the PNG signature + IHDR header."""
import os, solve
from solve import X, C0, D1, E1

# 1) embedded block-1 cipher reproduces the known oracle points
oracle = [(bytes(16),              '0a122be22e72a5237e5a0c1ddf6ff3f2'),
          (bytes(range(16)),       'bbdbb0ad7bec31415dc7798ae46b0057'),
          (b'\xff'*16,             '3cff3e66e821cf94bbad1308931ae7bf')]
ok = all(E1(p).hex() == h for p, h in oracle)
print('block-1 cipher matches oracle :', ok)
assert ok

# 2) decrypt block 1 of the real file -> PNG header
ENC = os.environ.get('ENC', './hello_png.enc')
data = open(ENC, 'rb').read()
CB = [data[i:i+16] for i in range(0, len(data), 16)]
P1 = X(D1(CB[1]), CB[0])
print('decrypted block 1            :', P1.hex())
good = P1[:8] == bytes.fromhex('89504e470d0a1a0a')
print('PNG signature present        :', good)
assert good
print('OK - ready to run run_parallel.sh')
