#!/usr/bin/env python3
"""
URANUS solver  --  recovers the 16-byte per-connection key and submits for the flag.

Two vulnerabilities:
  (1) ShiftColumns and MixColumns both act only WITHIN each column set {i,i+4,i+8,i+12},
      so URANUS is really 4 independent 32-bit ciphers (true for every f).
  (2) When the secret odd-round order f ends in "SB" (prob 6/24 = 1/4), each odd round's
      trailing SB merges with the next even round's leading SB (SB.SB = a fixed keyless
      bijection), collapsing 6 rounds -> 3 rounds per column.

Attack: per 32-bit column, integral (Square) attack with a 2-round key peel.  The peel
matrix Minv^2 = [[5,0,4,0],[0,5,0,4],[4,0,5,0],[0,4,0,5]] is block-structured, so it
decouples into two independent 2-byte searches (output indices {0,2} and {1,3}),
turning a 2^64 search into 2 * 2^16.  Using several 256-text Lambda-sets and requiring a
single shared peel constant b across sets pins down a = Minv*K6c uniquely.  Then
K6c = M*a for all 4 columns gives round_keys[6]; inverting the key schedule yields the key.

Connections whose f does not end in SB yield no candidates and are abandoned (~10 s);
reconnect until a favorable one appears (avg 4 tries).

Usage:  python3 solve_standalone.py <host> <port>
Requires: numpy
"""
import socket, itertools, time, random, sys
import numpy as np

# ----------------------------------------------------------------------------------
#  Tables: AES S-box (from the challenge), its inverse, and GF(2^8) multiply tables
# ----------------------------------------------------------------------------------
SBOX = (
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16)
SBOX_INV = [0]*256
for _i, _v in enumerate(SBOX): SBOX_INV[_v] = _i

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80; a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p

GF = {k: tuple(_gmul(k, x) for x in range(256)) for k in (2, 3, 9, 11, 13, 14)}
RCON = ([0x01,0,0,0],[0x02,0,0,0],[0x04,0,0,0],[0x08,0,0,0],[0x10,0,0,0],[0x20,0,0,0])

# ----------------------------------------------------------------------------------
#  Linear algebra over GF(2^8): MixColumns matrix M, its inverse, and Minv^2
# ----------------------------------------------------------------------------------
M = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
def _xor_all(it):
    r = 0
    for x in it: r ^= x
    return r
def _matmul(A, B):
    return [[_xor_all(_gmul(A[i][k], B[k][j]) for k in range(4)) for j in range(4)] for i in range(4)]
def _ginv(a):
    for b in range(1, 256):
        if _gmul(a, b) == 1: return b
    raise ValueError
def _inv_matrix(A):
    n = 4
    Aug = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(A)]
    for col in range(n):
        piv = next(r for r in range(col, n) if Aug[r][col] != 0)
        Aug[col], Aug[piv] = Aug[piv], Aug[col]
        inv = _ginv(Aug[col][col]); Aug[col] = [_gmul(inv, x) for x in Aug[col]]
        for r in range(n):
            if r != col and Aug[r][col] != 0:
                f = Aug[r][col]; Aug[r] = [a ^ _gmul(f, b) for a, b in zip(Aug[r], Aug[col])]
    return [row[n:] for row in Aug]
MINV  = _inv_matrix(M)            # [[14,11,13,9],...]
MINV2 = _matmul(MINV, MINV)       # block-structured [[5,0,4,0],[0,5,0,4],[4,0,5,0],[0,4,0,5]]
def mv(Mat, v):                   # 4x4 matrix * 4-vector over GF(2^8)
    return [_xor_all(_gmul(Mat[i][j], v[j]) for j in range(4)) for i in range(4)]

# ----------------------------------------------------------------------------------
#  Reference URANUS (configurable f) -- only used to verify a recovered key
# ----------------------------------------------------------------------------------
def transpose(m): return [m[4*j+i] for i in range(4) for j in range(4)]
def _vxor(a, b):  return [x ^ y for x, y in zip(a, b)]
def expand_key(key, rounds=6):
    rk = [[c for c in key]]
    for r in range(rounds):
        prev = rk[r]; w = prev[-4:]; w = w[1:] + w[:1]; w = [SBOX[i] for i in w]
        w = _vxor(_vxor(w, prev[:4]), RCON[r])
        for i in range(0, 12, 4): w += _vxor(w[i:i+4], prev[i+4:i+8])
        rk.append(w)
    return [transpose(k) for k in rk]
_SCP = [0,13,10,7, 4,1,14,11, 8,5,2,15, 12,9,6,3]
def _sb(s):  return [SBOX[c] for c in s]
def _sc(s):  return [s[_SCP[i]] for i in range(16)]
def _mc(st):
    s = [0]*16
    for i in range(4):
        s[i]    = GF[2][st[i]]^GF[3][st[i+4]]^st[i+8]^st[i+12]
        s[i+4]  = st[i]^GF[2][st[i+4]]^GF[3][st[i+8]]^st[i+12]
        s[i+8]  = st[i]^st[i+4]^GF[2][st[i+8]]^GF[3][st[i+12]]
        s[i+12] = GF[3][st[i]]^st[i+4]^st[i+8]^GF[2][st[i+12]]
    return s
class Lab:
    def __init__(self, key, f, rounds=6):
        self.rk = expand_key(key, rounds); self.f = list(f); self.rounds = rounds
    def _apply(self, s, op, rn):
        if op == "SB": return _sb(s)
        if op == "SC": return _sc(s)
        if op == "MC": return _mc(s)
        return _vxor(s, self.rk[rn])               # "AK"
    def encrypt_block(self, pt):
        s = _vxor(transpose(list(pt)), self.rk[0])
        for rn in range(1, self.rounds+1):
            order = ["SB","SC","MC","AK"] if rn % 2 == 0 else self.f
            for op in order: s = self._apply(s, op, rn)
        return bytes(transpose(s))

# ----------------------------------------------------------------------------------
#  Fast column key recovery (numpy)
# ----------------------------------------------------------------------------------
S2I = np.array([SBOX_INV[SBOX_INV[i]] for i in range(256)], dtype=np.uint8)   # SB.SB inverse
AR  = np.arange(256, dtype=np.uint8)
GMnp = {k: np.array(GF.get(k) or tuple(_gmul(k, x) for x in range(256)), dtype=np.uint8) for k in range(256)}
_T   = S2I[(AR[:, None] ^ AR[None, :])]                                        # T[v,b] = S2I[v^b]
_TBIG = np.concatenate([((_T >> j) & 1).astype(np.float32) for j in range(8)], axis=1)  # (256,2048)

def _par_n(qall, N):
    flat = ((np.arange(N, dtype=np.int64) * 256)[:, None] + qall.astype(np.int64)).reshape(-1)
    return (np.bincount(flat, minlength=N*256) & 1).reshape(N, 256).astype(np.float32)

def _zmask(par):
    """True at (candidate, b) where XOR_t S2I[q^b] == 0 is possible (i.e. balance can vanish)."""
    r  = par @ _TBIG
    rr = (np.rint(r).astype(np.int8) & 1).reshape(par.shape[0], 8, 256)
    return ~rr.any(axis=1)

def _qfull(P, i0, i1):
    A0 = S2I[(P[:, i0][None, :] ^ AR[:, None])]; A1 = S2I[(P[:, i1][None, :] ^ AR[:, None])]
    m = MINV2
    q0 = (GMnp[m[i0][i0]][A0][:, None, :] ^ GMnp[m[i0][i1]][A1][None, :, :]).reshape(65536, 256)
    q1 = (GMnp[m[i1][i0]][A0][:, None, :] ^ GMnp[m[i1][i1]][A1][None, :, :]).reshape(65536, 256)
    return q0, q1

def _qsub(P, i0, i1, a0s, a2s):
    A0 = S2I[P[:, i0][None, :] ^ a0s[:, None]]; A2 = S2I[P[:, i1][None, :] ^ a2s[:, None]]
    m = MINV2
    q0 = GMnp[m[i0][i0]][A0] ^ GMnp[m[i0][i1]][A2]
    q1 = GMnp[m[i1][i0]][A0] ^ GMnp[m[i1][i1]][A2]
    return q0, q1

def _recover_half(sets, i0, i1):
    """Return list of (a[i0], a[i1]) consistent with all Lambda-sets."""
    q0, q1 = _qfull(sets[0], i0, i1)
    M0 = _zmask(_par_n(q0, 65536)); M1 = _zmask(_par_n(q1, 65536))
    ok = M0.any(1) & M1.any(1); cand = np.nonzero(ok)[0]
    a0s = (cand // 256).astype(np.uint8); a2s = (cand % 256).astype(np.uint8)
    cm0 = M0[cand]; cm1 = M1[cand]
    for P in sets[1:]:
        q0, q1 = _qsub(P, i0, i1, a0s, a2s); N = len(cand)
        cm0 = cm0 & _zmask(_par_n(q0, N)); cm1 = cm1 & _zmask(_par_n(q1, N))
        keep = cm0.any(1) & cm1.any(1)
        cand, a0s, a2s, cm0, cm1 = cand[keep], a0s[keep], a2s[keep], cm0[keep], cm1[keep]
        if len(cand) <= 1: break
    return [(int(a0s[i]), int(a2s[i])) for i in range(len(cand))]

def _recover_col(sets):
    """Return list of candidate a = Minv*K6c (4 bytes) for one column."""
    h02 = _recover_half(sets, 0, 2)
    if not h02: return []
    h13 = _recover_half(sets, 1, 3)
    if not h13: return []
    return [[a0, a1, a2, a3] for (a0, a2) in h02 for (a1, a3) in h13]

# ----------------------------------------------------------------------------------
#  Assemble round_keys[6] from the 4 column keys, invert the key schedule
# ----------------------------------------------------------------------------------
def _assemble_rk6(K6cols):
    rk = [0]*16
    for c in range(4): rk[c], rk[c+4], rk[c+8], rk[c+12] = K6cols[c]
    return rk

def _invert_schedule(rk6_stored):
    rk = transpose(list(rk6_stored))                # un-transpose -> natural [W0,W1,W2,W3]
    for r in range(5, -1, -1):
        W0, W1, W2, W3 = rk[0:4], rk[4:8], rk[8:12], rk[12:16]
        pW3 = [W3[i] ^ W2[i] for i in range(4)]
        pW2 = [W2[i] ^ W1[i] for i in range(4)]
        pW1 = [W1[i] ^ W0[i] for i in range(4)]
        rot = pW3[1:] + pW3[:1]; sub = [SBOX[x] for x in rot]
        pW0 = [W0[i] ^ sub[i] ^ RCON[r][i] for i in range(4)]
        rk = pW0 + pW1 + pW2 + pW3
    return bytes(rk)

def recover_master(sets_per_col):
    """sets_per_col[c] = list of Lambda-sets (each (256,4) array of p=Minv*ct). [] if unattackable."""
    col_cands = []
    for c in range(4):
        ca = _recover_col(sets_per_col[c])
        if not ca: return []
        col_cands.append([mv(M, a) for a in ca])    # K6c = M * a
    return [_invert_schedule(_assemble_rk6(list(combo))) for combo in itertools.product(*col_cands)]

# ----------------------------------------------------------------------------------
#  Oracle (line protocol: send hex of N*16 bytes, get hex of N*16 bytes; prompt "> ")
# ----------------------------------------------------------------------------------
class Oracle:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port))
        self.f = self.s.makefile('rwb', buffering=0)
        self._wait_prompt()
    def _wait_prompt(self):
        buf = b''
        while not buf.endswith(b'> '):
            ch = self.f.read(1)
            if not ch: break
            buf += ch
    def enc(self, blocks: bytes) -> bytes:
        self.f.write(blocks.hex().encode() + b'\n')
        line = self.f.readline().strip()
        self._wait_prompt()
        return bytes.fromhex(line.decode())
    def submit(self, keyhex: str) -> str:
        self.f.write(b'SUBMIT ' + keyhex.encode() + b'\n')
        return self.f.read().decode(errors='ignore')
    def close(self):
        try: self.s.close()
        except Exception: pass

def _ct_to_p(ct):
    sc = transpose(list(ct))
    return [mv(MINV, [sc[c], sc[c+4], sc[c+8], sc[c+12]]) for c in range(4)]   # p per column

def collect_all(orc, nsets, rng):
    """One batched Lambda-set per (column, set-index): vary plaintext byte 4c+active over 0..255."""
    sets_per_col = [[] for _ in range(4)]
    known = None
    for c in range(4):
        for s in range(nsets):
            active = s % 4
            base = bytearray(rng.randbytes(16))
            blocks = bytearray()
            for v in range(256):
                blk = bytearray(base); blk[4*c + active] = v; blocks += blk
            ctcat = orc.enc(bytes(blocks))
            P = np.empty((256, 4), np.uint8)
            for v in range(256):
                ct = ctcat[16*v:16*v+16]
                sc = transpose(list(ct))
                P[v] = mv(MINV, [sc[c], sc[c+4], sc[c+8], sc[c+12]])
            sets_per_col[c].append(P)
            if known is None:                       # keep one (pt,ct) pair for verification
                pt0 = bytearray(base); pt0[4*c + active] = 0
                known = (bytes(pt0), ctcat[0:16])
    return sets_per_col, known

ALLF = [list(p) for p in itertools.permutations(["SB", "SC", "MC", "AK"])]

def attempt(orc, rng, nsets=3):
    spc, (pt, ct) = collect_all(orc, nsets, rng)
    for mk in recover_master(spc):
        for ff in ALLF:                              # f is secret; some order must reproduce ct
            if Lab(mk, ff).encrypt_block(pt) == ct:
                return mk
    return None

def solve(host, port, max_tries=64):
    for t in range(max_tries):
        orc = Oracle(host, port)
        rng = random.Random()
        try:
            t0 = time.time(); mk = attempt(orc, rng); dt = time.time() - t0
            if mk:
                print("[+] recovered key = %s  (%.1fs)" % (mk.hex(), dt))
                resp = orc.submit(mk.hex())
                print("[+] server:", resp.strip())
                orc.close(); return mk
            print("[-] try %2d: f not favorable (%.1fs), reconnecting..." % (t, dt))
        except Exception as e:
            print("[!] try %2d: error %r" % (t, e))
        orc.close()
    print("[x] gave up after %d tries" % max_tries)
    return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: python3 solve_standalone.py <host> <port>"); sys.exit(1)
    solve(sys.argv[1], int(sys.argv[2]))