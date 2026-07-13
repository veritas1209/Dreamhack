#!/usr/bin/env python3
"""
Decrypt ONE CBC block of hello_png.enc.  Independent unit -> fully parallelizable.

Usage:
    python3 decrypt_block.py <block_index>

Env vars (with defaults):
    CHAL   path to the encryptor binary           (./chal)
    ENC    path to hello_png.enc                  (./hello_png.enc)
    OUTDIR directory for per-block results         (./results)
    TMPDIR scratch dir for crafted inputs          (/tmp)

Writes <OUTDIR>/<index:05d>.bin (16 raw plaintext bytes).
Block index ranges 1..(N-1) where N = number of 16-byte blocks in the file.
Block 0 is the encryptor's internal CONST block and is not part of the output.
"""
import os, sys, subprocess, tempfile
import solve
from solve import X, C0, D1, E1, make_dec, recover_cipher
import tracer

CHAL   = os.environ.get('CHAL',   './chal')
ENC    = os.environ.get('ENC',    './hello_png.enc')
OUTDIR = os.environ.get('OUTDIR', './results')
TMPDIR = os.environ.get('TMPDIR', '/tmp')

def cipher_blocks():
    data = open(ENC, 'rb').read()
    return [data[i:i+16] for i in range(0, len(data), 16)]

def encrypt(path):
    """Run the encryptor on `path`, return its ciphertext block list."""
    enc = path + '.enc'
    try: os.remove(enc)
    except FileNotFoundError: pass
    subprocess.run([CHAL, path], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    d = open(enc, 'rb').read()
    return [d[i:i+16] for i in range(0, len(d), 16)]

def decrypt_block(idx, CB):
    Cprev, Ci = CB[idx-1], CB[idx]
    if idx == 1:                                   # block 1: keys already known
        return X(D1(Ci), Cprev)

    # Craft a 2-user-block file whose first ciphertext block == Cprev, so that
    # the second user block is encrypted with exactly E_{f(Cprev)} = block-idx's cipher.
    P1 = X(D1(Cprev), C0)
    tag = '%05d' % idx
    fa = os.path.join(TMPDIR, 'cam_%s_a.bin' % tag)   # traced variant
    fb = os.path.join(TMPDIR, 'cam_%s_b.bin' % tag)   # validation variant
    junkA = b'AAAAAAAAAAAAAAA'; junkB = b'BBBBBBBBBBBBBBB'
    open(fa, 'wb').write(P1 + junkA)
    open(fb, 'wb').write(P1 + junkB)

    cbA = encrypt(fa)
    assert cbA[1] == Cprev, 'crafted C1 != Cprev (D1/keys mismatch)'
    cbB = encrypt(fb)
    X2a = X(junkA + b'\x01', Cprev); C2a = cbA[2]
    X2b = X(junkB + b'\x01', Cprev); C2b = cbB[2]

    acc = tracer.trace(CHAL, fa, max_groups=2000)
    keys = recover_cipher(acc, X2a, C2a, X2b, C2b)
    for f in (fa, fb, fa+'.enc', fb+'.enc'):
        try: os.remove(f)
        except FileNotFoundError: pass
    if keys is None:
        raise RuntimeError('block %d: cipher recovery failed' % idx)
    D = make_dec(*keys)
    return X(D(Ci), Cprev)

def main():
    idx = int(sys.argv[1])
    os.makedirs(OUTDIR, exist_ok=True)
    out = os.path.join(OUTDIR, '%05d.bin' % idx)
    if os.path.exists(out) and os.path.getsize(out) == 16:
        return                                       # resume-friendly: skip done
    CB = cipher_blocks()
    P = decrypt_block(idx, CB)
    with open(out, 'wb') as f:
        f.write(P)

if __name__ == '__main__':
    main()
