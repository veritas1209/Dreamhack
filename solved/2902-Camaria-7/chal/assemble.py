#!/usr/bin/env python3
"""
Assemble per-block plaintext (results/NNNNN.bin) into the final PNG.

Env: ENC (default ./hello_png.enc), OUTDIR (default ./results),
     OUT (default ./hello.png)
"""
import os, sys

ENC    = os.environ.get('ENC',    './hello_png.enc')
OUTDIR = os.environ.get('OUTDIR', './results')
OUT    = os.environ.get('OUT',    './hello.png')

def main():
    nblk = os.path.getsize(ENC) // 16
    last = nblk - 1
    pt = bytearray()
    missing = []
    for i in range(1, last + 1):
        p = os.path.join(OUTDIR, '%05d.bin' % i)
        if not (os.path.exists(p) and os.path.getsize(p) == 16):
            missing.append(i); continue
        pt += open(p, 'rb').read()
    if missing:
        print('WARNING: %d blocks missing (e.g. %s). Re-run run_parallel.sh.'
              % (len(missing), missing[:10]))
        return 1
    # sanity: PNG signature
    if pt[:8] != bytes.fromhex('89504e470d0a1a0a'):
        print('WARNING: PNG signature not found; first bytes:', pt[:8].hex())
    # strip PKCS7 padding
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        pt = pt[:-pad]
    with open(OUT, 'wb') as f:
        f.write(pt)
    print('wrote', OUT, '(%d bytes)' % len(pt),
          '- IEND present:', pt[-8:] == b'IEND\xaeB`\x82')
    return 0

if __name__ == '__main__':
    sys.exit(main())
