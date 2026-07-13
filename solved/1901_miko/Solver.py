import random, hashlib, functools, operator, time
from mcnie import (gmul, ginv, bin2gf, gf2bin_bytes, build_affine, gf2_rank,
                   blk, n, k, l, nk, r, M_, MASK, vec_mat, build_GF)

def popcnt_parity(v):
    return bin(v).count('1') & 1

def gf2_kernel(rows, ncols):
    """rows: list of ints (each a row, bit j = col j). Return basis of right-kernel."""
    rows = [r_ & ((1<<ncols)-1) for r_ in rows]
    pivot_col_of_row = []
    where = {}            # pivot column -> row (reduced)
    for rw in rows:
        cur = rw
        for pc, prow in where.items():
            if (cur >> pc) & 1:
                cur ^= prow
        if cur:
            pc = (cur & -cur).bit_length() - 1   # lowest set bit
            where[pc] = cur
    pivots = set(where.keys())
    # back-reduce
    pcs = sorted(where.keys())
    for i in range(len(pcs)):
        for jp in pcs[i+1:]:
            if (where[pcs[i]] >> jp) & 1:
                where[pcs[i]] ^= where[jp]
    free = [c for c in range(ncols) if c not in pivots]
    basis = []
    for f in free:
        vec = 1 << f
        for pc, prow in where.items():
            if (prow >> f) & 1:
                vec |= (1 << pc)
        basis.append(vec)
    return basis

class Solver:
    def __init__(self, pk_bytes, c1, c2):
        self.pk_gf = bin2gf(pk_bytes, blk*5)
        self.a, self.C = build_affine(self.pk_gf, c1, c2)
        self.c1 = c1
        # precompute columns: alpha-block gmul(a_j, 1<<b); u_t block gmul(C[j][t],1<<b)
        col_a = [[gmul(self.a[j], 1<<b) for b in range(M_)] for j in range(n)]
        col_C = [[[gmul(self.C[j][t], 1<<b) for b in range(M_)]
                  for t in range(blk)] for j in range(n)]
        # Mj[j][i] = 209-bit row: dependency of (V_j bit i) on the (alpha,u) input bits
        ncols = M_*(blk+1)
        self.ncols = ncols
        self.Mj = []
        for j in range(n):
            rowsj = [0]*M_
            for b in range(M_):
                ca = col_a[j][b]
                for i in range(M_):
                    if (ca >> i) & 1:
                        rowsj[i] |= (1 << b)
            for t in range(blk):
                base = M_*(t+1)
                for b in range(M_):
                    cc = col_C[j][t][b]
                    for i in range(M_):
                        if (cc >> i) & 1:
                            rowsj[i] |= (1 << (base + b))
            self.Mj.append(rowsj)

    def e_of_x(self, x):
        return [self.a[j] ^ functools.reduce(operator.xor,
                (gmul(x[t], self.C[j][t]) for t in range(blk)), 0) for j in range(n)]

    def attempt(self, P):
        """P: functionals defining W=ker(P). homogeneous system in (alpha,u) -> kernel."""
        rows = []
        Mj = self.Mj
        for j in range(n):
            mr = Mj[j]
            for p in P:
                acc = 0
                pp = p; i = 0
                while pp:
                    if pp & 1: acc ^= mr[i]
                    pp >>= 1; i += 1
                rows.append(acc)
        return gf2_kernel(rows, self.ncols)

    def extract(self, vec):
        alpha = vec & MASK
        if alpha == 0:
            return None
        ainv = ginv(alpha)
        x = []
        base = M_
        for t in range(blk):
            u = (vec >> base) & MASK
            x.append(gmul(u, ainv))
            base += M_
        return x

def random_P(w):
    """return 19-w independent functionals (ker = random w-dim W)."""
    nf = M_ - w
    while True:
        P = [random.getrandbits(M_) for _ in range(nf)]
        # check independence (rank nf)
        if len(gf2_kernel(P[:], M_)) == M_ - nf:   # kernel dim = w
            return P

def solve(pk_bytes, c1, c2, want_hash=None, w=13, max_iter=4000):
    S = Solver(pk_bytes, c1, c2)
    for it in range(1, max_iter+1):
        P = random_P(w)
        basis = S.attempt(P)
        if not basis:
            continue
        # enumerate small combinations of kernel basis
        d = len(basis)
        cand_vecs = []
        if d <= 12:
            for mask in range(1, 1<<d):
                v = 0
                mm = mask; idx = 0
                while mm:
                    if mm & 1: v ^= basis[idx]
                    mm >>= 1; idx += 1
                cand_vecs.append(v)
        else:
            cand_vecs = basis
        for v in cand_vecs:
            x = S.extract(v)
            if x is None:
                continue
            e = S.e_of_x(x)
            if gf2_rank(e) <= r:
                # recover m
                m = recover_m(S, x, c2)
                pt = gf2bin_bytes(m, 71)
                if want_hash is None or hashlib.sha256(pt).hexdigest().upper() == want_hash.upper():
                    return pt, it
    return None, max_iter

def recover_m(S, x, c2):
    # m[j] for j<k = c2[j] ^ (xB)[j]; m[k+t]=x_t
    G, F = build_GF(S.pk_gf)
    m = [0]*l
    for t in range(blk):
        m[k+t] = x[t]
    for j in range(k):
        acc = c2[j]
        for t in range(blk):
            acc ^= gmul(x[t], F[k+t][j])
        m[j] = acc
    return m

if __name__ == '__main__':
    from mcnie import parse_line
    lines = open('dvec.txt').read().strip().split('\n')
    pk = parse_line(lines[0]); pt_true = parse_line(lines[1]); ct = parse_line(lines[2])
    ct_gf = bin2gf(ct, n+nk); c1 = ct_gf[:n]; c2 = ct_gf[n:]
    want = hashlib.sha256(pt_true).hexdigest().upper()
    random.seed(1234)
    t0 = time.time()
    pt, iters = solve(pk, c1, c2, want_hash=want)
    dt = time.time() - t0
    print('iters =', iters, 'time = %.3fs' % dt)
    print('recovered pt == true pt :', pt == pt_true)
    print('sha256 match            :', pt is not None and hashlib.sha256(pt).hexdigest().upper()==want)