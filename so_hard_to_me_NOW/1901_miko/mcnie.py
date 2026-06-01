import sys

# ---- GF(2^19), modulus base_poly[19] = 0x80027 (x^19+x^5+x^2+x+1) ----
M_  = 19
BP  = 0x80027
HI  = 1 << (M_ - 1)
MASK = (1 << M_) - 1

def gmul(x, y):
    r = 0
    while y:
        if y & 1: r ^= x
        if x & HI: x = (x << 1) ^ BP
        else:      x <<= 1
        y >>= 1
    return r

def gpow(x, e):
    r = 1
    while e:
        if e & 1: r = gmul(r, x)
        x = gmul(x, x); e >>= 1
    return r

def ginv(x):
    if x == 0: return 0
    return gpow(x, (1 << M_) - 2)

# ---- bin2gf : port of gf.c (reads xlen gf elements from bytes) ----
def bin2gf(d, xlen):
    x = [0] * xlen
    x[0] = d[0]
    res = M_ - 8
    i, j = 0, 1
    while i < xlen:
        if res > 8:
            a = d[j]
            x[i] |= a << (M_ - res)
            res -= 8
        else:
            a = d[j]
            flag = (1 << res) - 1
            x[i] |= (a & flag) << (M_ - res); i += 1
            if i >= xlen: break
            x[i] = a >> res
            res = M_ - (8 - res)
        j += 1
    return [v & MASK for v in x]

# ---- gf2bin : port of gf.c (gf elements -> bytes, little-endian uint64) ----
def gf2bin_bytes(x, nbytes):
    xlen = len(x)
    dlen = (M_ * xlen - 1) // 64 + 1
    d = [0] * dlen
    res = 64; j = 0
    for i in range(xlen):
        y = x[i] & MASK
        if res >= M_:
            d[j] |= y << (64 - res)
            res -= M_
            if res == 0: res = 64; j += 1
        else:
            flag = (1 << res) - 1
            d[j] |= (y & flag) << (64 - res); j += 1
            d[j] = y >> res
            res += 64 - M_
    out = b''.join(int(v & ((1<<64)-1)).to_bytes(8, 'little') for v in d)
    return out[:nbytes]

# ---- parameters ----
blk = 10
n   = blk * 4      # 40
k   = blk * 2      # 20
l   = blk * 3      # 30
nk  = n - k        # 20
r   = 4

def build_GF(pk_gf):
    """Reconstruct G' (l x n) and F (l x nk) exactly as encrypt_one_block does."""
    blk2, blk3, blk4 = 2*blk, 3*blk, 4*blk
    # G0 = identity(l) in first l cols
    G = [[0]*n for _ in range(l)]
    for i in range(l): G[i][i] = 1
    for j in range(blk):
        G[0][l+j]    = pk_gf[j]
        G[blk][l+j]  = pk_gf[blk+j]
        G[blk2][l+j] = pk_gf[blk2+j]
    for i in range(1, blk):  # circulant
        G[i][l]      = G[i-1][n-1]
        G[blk+i][l]  = G[blk+i-1][n-1]
        G[blk2+i][l] = G[blk2+i-1][n-1]
        for j in range(l+1, n):
            G[i][j]      = G[i-1][j-1]
            G[blk+i][j]  = G[blk+i-1][j-1]
            G[blk2+i][j] = G[blk2+i-1][j-1]
    # F = identity(nk) in rows 0..nk-1
    F = [[0]*nk for _ in range(l)]
    for i in range(nk): F[i][i] = 1
    for j in range(nk):
        F[nk][j] = pk_gf[blk3+j]
    for i in range(nk+1, l):  # circulant rows
        F[i][0]   = F[i-1][blk-1]
        F[i][blk] = F[i-1][nk-1]
        for j in range(1, blk):
            F[i][j]      = F[i-1][j-1]
            F[i][blk+j]  = F[i-1][blk+j-1]
    return G, F

def vec_mat(m, Mt, rows, cols):
    """ (m . M)  where m length rows, M is rows x cols """
    out = [0]*cols
    for j in range(cols):
        acc = 0
        for i in range(rows):
            if m[i]: acc ^= gmul(m[i], Mt[i][j])
        out[j] = acc
    return out

def gf2_rank(elts):
    """rank over GF(2) of a list of GF(2^19) elements (as 19-bit vectors)"""
    basis = []
    for v in elts:
        x = v
        for b in basis:
            x = min(x, x ^ b)
        if x: basis.append(x); basis.sort(reverse=True)
    # proper gaussian:
    basis = []
    for v in elts:
        x = v
        for b in basis:
            if x ^ b < x: x ^= b
        if x: basis.append(x); basis.sort(reverse=True)
    return len([b for b in basis if b])

def parse_line(line):
    return bytes.fromhex(line.split('=',1)[1].strip())

import functools, operator

def build_affine(pk_gf, c1, c2):
    """e_j(x) = a[j] ^ sum_t gmul(x_t, C[j][t]),  x = m[20:30] (10 unknowns)."""
    G, F = build_GF(pk_gf)
    # m0 = m(x=0): m0[j]=c2[j] for j<k, 0 for j>=k
    m0 = [c2[j] if j < k else 0 for j in range(l)]
    mG0 = vec_mat(m0, G, l, n)
    a = [c1[j] ^ mG0[j] for j in range(n)]
    # C[j][t] = (sum_{i<k} gmul(F[k+t][i], G[i][j])) ^ G[k+t][j]
    C = [[0]*blk for _ in range(n)]
    for j in range(n):
        for t in range(blk):
            acc = G[k+t][j]
            for i in range(k):
                bti = F[k+t][i]
                if bti: acc ^= gmul(bti, G[i][j])
            C[j][t] = acc
    return a, C

if __name__ == '__main__':
    lines = open('dvec.txt').read().strip().split('\n')
    pk = parse_line(lines[0]); pt = parse_line(lines[1]); ct = parse_line(lines[2])
    m_true = [int(t,16) for t in lines[3].split('=',1)[1].split()]
    print('sizes pk/pt/ct =', len(pk), len(pt), len(ct))

    pk_gf = bin2gf(pk, blk*5)        # 50
    ct_gf = bin2gf(ct, n+nk)         # 60
    pt_pad = pt + b'\x00'            # OOB byte fixed to 0 in harness
    m     = bin2gf(pt_pad, l)        # 30  (the message)
    print('python m == C m            :', m == m_true)
    c1 = ct_gf[:n]; c2 = ct_gf[n:n+nk]

    G, F = build_GF(pk_gf)

    # c2 should equal m . F  exactly (NO error)
    c2_chk = vec_mat(m, F, l, nk)
    print('c2 matches m.F (noise-free) :', c2_chk == c2)

    # e = c1 - m.G'
    mG = vec_mat(m, G, l, n)
    e  = [c1[j] ^ mG[j] for j in range(n)]
    print('rank_GF2(e)                 :', gf2_rank(e), '(expect <= r =', r, ')')

    # x = m[20:30] ; check e[20+t] = c1[20+t] ^ x_t
    x = m[k:l]
    ok = all(e[k+t] == (c1[k+t] ^ x[t]) for t in range(blk))
    print('e[20+t] == c1[20+t]^x_t     :', ok)

    # round-trip m -> pt[:71]
    print('gf2bin(m)[:71]==pt          :', gf2bin_bytes(m, len(pt)) == pt)

    # ---- build affine map e(x) = a + sum_t x_t * C[:,t] ----
    a_aff, C_aff = build_affine(pk_gf, c1, c2)
    x = m[k:l]
    e_aff = [a_aff[j] ^ functools.reduce(operator.xor,
              (gmul(x[t], C_aff[j][t]) for t in range(blk)), 0) for j in range(n)]
    print('affine e(x_true)==e         :', e_aff == e)