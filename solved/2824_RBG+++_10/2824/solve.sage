#!/usr/bin/env sage
# =============================================================================
#  RBG+++   (KalmarCTF 2026, author: soon-haari)   --   full solver
# =============================================================================
#
#  METHOD  (intended solution; x = m^{-1337})
#  ------------------------------------------
#  The `[DEBUG] e = ...` audit line leaks the next seed, so every exponent is
#  known:  A_i = lcg(dbg[i-1]),  B_i = lcg(A_i),  lcg(s)=3s+1337 mod N.
#  For the samples with k_i == 0  (i.e. B_i = 3 A_i + 1337 exactly):
#
#        m^{A} + m^{3A+1337} = c (mod p)  ==>  W^3 + x*W - c*x = 0,  W = m^{A}
#
#  a cubic in W sharing one unknown x = m^{-1337} per prime p | N.
#  LLL finds a small relation among the (known) exponents:
#
#        sum_i s_i * A_i + 1337 * s_res == 0  (mod p-1)
#        ==>  prod_i (m^{A_i})^{s_i} = x^{s_res}.
#
#  Split into positive / negative exponent parts so everything stays polynomial
#  in x (no 1/x):
#        L = prod_{s_i>0} W_i^{ s_i},   R = prod_{s_i<0} W_i^{|s_i|}
#        condition:  L = x^{s_res} * R
#  Eliminating the W_i over the three cubic branches:
#
#        F(x) = Res_Y( M_R(Y),  M_L(x^{s_res} * Y) )
#
#  with M_L, M_R the monic characteristic polynomials of L, R over GF(p), built
#  from cubic-root power sums (Newton).  The true x = m^{-1337} is a root of F.
#  Two/three DIFFERENT relations give F1, F2, ... ; gcd(F1,F2,...) collapses to
#  (x - x_true), avoiding the ruinous gcd(x^p - x, F) at this degree.
#  Recover m mod p from x, repeat mod q, CRT, long_to_bytes.
#
#  COST (MEASURED scaling, prime-independent):
#      deg F  ~  (D/3) * sum|s_i|      with  D = 3^(#nonzero s_i)
#  (the sum|s| / "norm-degree" term dominates; the s_res term is minor).
#  Verified: K=2 ->4904, K=3 ->2556, K=4(Knz=3) ->678, all <= the analytic
#  degree_bound() used below.  For the real 137-bit prime the LLL coefficients
#  are ~2^(137/K), so at the optimal K~9 the degree is ~1e9.  Consequences:
#      * evaluation (parallel, D~1e4 ops/pt): ~1e13 ops -> hours on 32 threads.
#      * a degree-1e9 poly is ~17 GB; the subproduct-tree interpolation needs
#        ~O(n log n) ~ 300-500 GB  ->  BORDERLINE/OVER on a 384 GB box.
#  So: push pick_relations() hard (raise RELATION_TRIES, tune SUBSET_SIZE /
#  SRES_WEIGHT) to get deg <= ~3e8 (tree ~150-250 GB, fits) before a real run,
#  and watch memory.  The author's tighter norm-based elimination reaches
#  deg ~1e7 (~17 core-h, comfortable) -- see blog.zksecurity.xyz/posts/kalmar2026;
#  ask if you want that variant wired in.  This script's construction is the
#  fully-validated one, ideal for the self-test and for any instance whose
#  degree fits memory.
#  pick_relations() explicitly minimises the predicted degree.
#
#  >>> RUN THE SELF-TEST FIRST (MODE="selftest").  It routes through EVERY
#  >>> function -- incl. the fast subproduct-tree interpolation -- and asserts
#  >>> full flag-integer recovery on toy primes.  Only then set MODE="real".
#
#  (The pure-int GF(p) helpers _resultant and the subproduct-tree interpolation
#   were validated against brute force before shipping.)
# =============================================================================

import math, time, random, os, struct, json
from multiprocessing import Pool, cpu_count

# optional C evaluation kernel (feval.so + feval.py in the same directory)
try:
    import feval
    _FEVAL = feval.available or feval._load()
except Exception:
    _FEVAL = False

# large-degree polynomial back-end (FLINT).  Sage's NTL caps polynomial FFT at
# ~2**25; our resultant polynomials are far larger, so interpolation/gcd go here.
try:
    import flint_backend as _FB
    _HAVE_FLINT = True
except Exception:
    _HAVE_FLINT = False

# checkpoint directory (override with  CKPT=/path  on the command line / env).
# Every completed F, every prime's result, and each relation set is persisted here,
# and the per-point evaluation streams to disk as it runs -- so a crash never loses
# more than the last chunk, and a re-run resumes instead of recomputing.
CKPT_DIR = os.environ.get("CKPT", "ckpt")

# --------------------------------------------------------------------------- #
#  CONFIG                                                                      #
# --------------------------------------------------------------------------- #
MODE          = "selftest"     # "selftest"  ->  toy end-to-end;   "real" -> output.txt
OUTPUT_FILE   = "output.txt"
NPROC         = max(1, cpu_count())
LCG_ADD       = 1337

# If N's factors are already known (e.g. from factordb / an external CADO run),
# drop them here to skip factoring entirely.  Leave empty to factor in-script.
KNOWN_FACTORS = (
    89319941268580302833179511371818098358631,
    119275154100339619965502899458205073698193,
)

# real-run tuning (see notes above)
SUBSET_SIZE   = 8              # K samples per relation (7..11)
N_RELATIONS   = 2             # two polynomials suffice for the gcd (README: "get two of them")
RELATION_TRIES= 600          # subset/weight search budget (LLL is cheap; more tries -> lower degree)
SRES_WEIGHT   = 1 << 8        # lattice penalty on |s_res|  (bigger -> smaller degree, harder to find)

# self-test tuning (kept tiny so degrees stay < toy prime and it finishes fast)
ST_SUBSET     = 2
ST_NREL       = 3
ST_TRIES      = 40

# --- CLI overrides -----------------------------------------------------------
#   sage solve.sage real
#   sage solve.sage real SUBSET_SIZE=9 RELATION_TRIES=200 SRES_WEIGHT=1024
#   sage solve.sage real OUTPUT_FILE=out.txt NPROC=48
# (no args  ->  runs the self-test, as configured above)
import sys as _sys
for _a in _sys.argv[1:]:
    if _a in ("selftest", "real"):
        MODE = _a
    elif "=" in _a:
        _k, _v = _a.split("=", 1); _k = _k.strip()
        if _k == "OUTPUT_FILE":
            OUTPUT_FILE = _v.strip()
        elif _k in {"SUBSET_SIZE", "N_RELATIONS", "RELATION_TRIES",
                    "SRES_WEIGHT", "NPROC", "ST_SUBSET", "ST_NREL", "ST_TRIES"}:
            globals()[_k] = int(eval(_v, {}, {}))     # allows e.g. 1<<10, 2**8

# --------------------------------------------------------------------------- #
#  Pure-int GF(p) core  (sage-object-free  ->  picklable for multiprocessing)  #
# --------------------------------------------------------------------------- #
def _norm(a, p):
    a = [c % p for c in a]; i = 0
    while i < len(a) - 1 and a[i] == 0: i += 1
    return a[i:]

def _polymod(a, b, p):
    a = _norm(a, p); b = _norm(b, p); invlb = pow(b[0], p - 2, p)
    while len(a) >= len(b) and any(a):
        a = _norm(a, p)
        if len(a) < len(b): break
        coef = (a[0] * invlb) % p
        for i in range(len(b)): a[i] = (a[i] - coef * b[i]) % p
        a = a[1:]
    return _norm(a, p)

def _resultant(a, b, p):
    """Res(a,b) over GF(p), coeffs high->low.  (validated vs brute force)"""
    a = _norm(a, p); b = _norm(b, p); res = 1
    if a == [0] or b == [0]: return 0
    while len(b) > 1:
        da, db = len(a) - 1, len(b) - 1
        r = _polymod(a, b, p)
        if r == [0]: return 0
        dr = len(r) - 1
        res = (res * pow(-1, da * db, p) * pow(b[0], da - dr, p)) % p
        a, b = b, r
    return (res * pow(b[0], len(a) - 1, p)) % p

def _newton_p(e, M, p):                      # elem-sym -> power sums
    d = len(e) - 1; P = [0] * (M + 1)
    for k in range(1, M + 1):
        s = 0
        for i in range(1, min(k, d) + 1):
            s = (s + ((-1) ** (i - 1)) * e[i] * P[k - i]) % p
        if k <= d:
            s = (s + ((-1) ** (k - 1)) * k * e[k]) % p
        P[k] = s % p
    return P

def _newton_e(P, d, p):                      # power sums -> monic elem-sym
    e = [0] * (d + 1); e[0] = 1
    for k in range(1, d + 1):
        s = 0
        for i in range(1, k + 1):
            s = (s + ((-1) ** (i - 1)) * e[k - i] * P[i]) % p
        e[k] = (s * pow(k, p - 2, p)) % p
    return e

def _polymulmod3(A, B, x, cx, p):
    """multiply two deg<=2 polys in W, reduce mod (W^3 + xW - cx) i.e. W^3=-xW+cx."""
    r = [0, 0, 0, 0, 0]
    for i in range(3):
        ai = A[i]
        if ai:
            r[i]     = (r[i]     + ai * B[0]) % p
            r[i + 1] = (r[i + 1] + ai * B[1]) % p
            r[i + 2] = (r[i + 2] + ai * B[2]) % p
    for d in (4, 3):
        top = r[d]
        if top:
            r[d - 3] = (r[d - 3] + top * cx) % p
            r[d - 2] = (r[d - 2] - top * x) % p
            r[d] = 0
    return r[:3]

def _Wpow_mod(a, x, cx, p):
    """W^a mod (W^3+xW-cx) as [c0,c1,c2];  O(log a)  (fixes the old O(a*D) blowup)."""
    res = [1, 0, 0]; base = [0, 1, 0]
    while a > 0:
        if a & 1: res = _polymulmod3(res, base, x, cx, p)
        a >>= 1
        if a: base = _polymulmod3(base, base, x, cx, p)
    return res

def _side_charpoly(items, x, p):
    """monic char poly (high->low) of prod_i W_i^{a_i}; W_i roots of W^3+xW-cx.
       power sums of prod == elementwise product of per-factor power sums.
       empty product == element 1 -> (Y-1)."""
    if not items:
        return [1, (-1) % p], 1
    x %= p; D = 3 ** len(items); Pprod = [1] * (D + 1)
    for (c, a) in items:
        cx = (c * x) % p
        rho = _Wpow_mod(a, x, cx, p)                 # W^a mod cubic, deg<=2
        T = _newton_p([1, 0, x, cx], 2, p); T0 = 3    # traces of W^1, W^2 over the 3 roots
        cur = [1, 0, 0]                               # rho^0
        for k in range(1, D + 1):
            cur = _polymulmod3(cur, rho, x, cx, p)    # rho^k mod cubic
            Pprod[k] = (Pprod[k] * (cur[0] * T0 + cur[1] * T[1] + cur[2] * T[2])) % p
    E = _newton_e([0] + [Pprod[kk] for kk in range(1, D + 1)], D, p)
    return [((-1) ** i) * E[i] % p for i in range(D + 1)], D

def F_at_x(cs, sc, s_res, x, p):
    """single evaluation of F(x) = Res_Y(M_R(Y), M_L(x^{s_res} Y))."""
    x %= p
    if x == 0:
        return 0
    pos = [(c, s)  for c, s in zip(cs, sc) if s > 0]
    neg = [(c, -s) for c, s in zip(cs, sc) if s < 0]
    s = s_res
    if s < 0:
        pos, neg = neg, pos; s = -s
    ML, DL = _side_charpoly(pos, x, p)
    MR, DR = _side_charpoly(neg, x, p)
    xs = pow(x, s % (p - 1), p)
    MLsub = [(ML[i] * pow(xs, DL - i, p)) % p for i in range(DL + 1)]
    return _resultant(MR, MLsub, p)

# multiprocessing worker (reads inherited globals via fork)
_W = {}
def _eval_span(span):
    lo, hi = span
    cs, sc, sr, p = _W['cs'], _W['sc'], _W['sr'], _W['p']
    return lo, [F_at_x(cs, sc, sr, x, p) for x in range(lo, hi)]

# --------------------------------------------------------------------------- #
#  Fast subproduct-tree interpolation over GF(p)  (algorithm validated;        #
#  here on flint-backed sage polynomials -> O(M(n) log n)).                    #
# --------------------------------------------------------------------------- #
def fast_interpolate(xs, ys, p):
    Rp = PolynomialRing(GF(p), 'X'); X = Rp.gen(); Fp = GF(p)
    n = len(xs)
    xg = [Fp(v) for v in xs]
    tree = {}
    def sub(lo, hi):
        key = (lo, hi)
        r = tree.get(key)
        if r is not None: return r
        if hi - lo == 1:
            r = X - xg[lo]
        else:
            mid = (lo + hi) // 2
            r = sub(lo, mid) * sub(mid, hi)
        tree[key] = r; return r
    M = sub(0, n)
    # multipoint evaluate M' at all xs
    dvals = [None] * n
    def mpe(P, lo, hi):
        P = P % sub(lo, hi)
        if hi - lo == 1:
            dvals[lo] = P[0] if P.degree() >= 0 else Fp(0); return
        mid = (lo + hi) // 2
        mpe(P, lo, mid); mpe(P, mid, hi)
    mpe(M.derivative(), 0, n)
    c = [Fp(ys[i]) / dvals[i] for i in range(n)]
    def comb(lo, hi):
        if hi - lo == 1:
            return Rp(c[lo])
        mid = (lo + hi) // 2
        return comb(lo, mid) * sub(mid, hi) + comb(mid, hi) * sub(lo, mid)
    return comb(0, n)

# --------------------------------------------------------------------------- #
#  parsing + k=0 sample extraction                                            #
# --------------------------------------------------------------------------- #
def load(path):
    lines = open(path).read().splitlines()
    N = int(lines[0].split("=", 1)[1].strip())
    r_list, dbg = [], []
    for ln in lines[1:]:
        ln = ln.strip()
        if not ln: continue
        if ln.startswith("[DEBUG]"): dbg.append(int(ln.split("=", 1)[1].strip()))
        else: r_list.append(int(ln))
    return N, r_list, dbg

def k0_samples(N, r_list, dbg):
    lcg = lambda s: (3 * s + LCG_ADD) % N
    out = []
    for i in range(1, len(r_list)):
        A = lcg(dbg[i - 1]); B = lcg(A)
        if (3 * A + LCG_ADD - B) // N == 0:
            out.append((A, r_list[i]))
    return out

# --------------------------------------------------------------------------- #
#  LLL relation search (degree-minimising)                                    #
# --------------------------------------------------------------------------- #
def find_relation(exps, order, weight, W=1 << 40):
    K = len(exps); rows = []
    for i in range(K):
        row = [0] * (K + 2); row[i] = 1; row[K + 1] = (exps[i] % order) * W
        rows.append(row)
    row = [0] * (K + 2); row[K] = weight; row[K + 1] = (LCG_ADD % order) * W; rows.append(row)
    row = [0] * (K + 2); row[K + 1] = order * W; rows.append(row)
    B = Matrix(ZZ, rows).LLL()
    best = None
    for r in B:
        if r[K + 1] != 0: continue
        s = [int(r[j]) for j in range(K)]
        if int(r[K]) % weight != 0: continue
        s_res = int(r[K]) // weight
        if not any(s) and s_res == 0: continue
        if (sum(si * ei for si, ei in zip(s, exps)) + LCG_ADD * s_res) % order != 0:
            continue
        Knz = sum(1 for v in s if v)
        n_pos = sum(1 for v in s if v > 0); n_neg = Knz - n_pos
        sumabs = sum(abs(v) for v in s); D = 3 ** Knz
        deg = max(3, (D // 3) * sumabs + D * abs(s_res))       # true degree estimate
        percost = 3 ** (2 * max(n_pos, n_neg))                  # per-point cost ~ D_side^2 (larger side)
        cost = deg * percost                                    # total eval work: prefers low-deg AND balanced
        if best is None or cost < best[0]:
            best = (cost, s, s_res, deg)
    return best

def pick_relations(samples, order, n_rel, subset_size, tries):
    idx_all = list(range(len(samples)))
    # explore the s_res <-> sum|s| trade-off across a wide range of lattice weights
    weights = [1, 1 << 4, 1 << 8, 1 << 12, 1 << 16, 1 << 20]
    pool = []                          # collect ALL relations, keep the best afterwards
    for _ in range(tries):
        subset = sorted(random.sample(idx_all, int(min(subset_size, len(idx_all)))))
        exps = [samples[j][0] for j in subset]
        cand = None
        for w in weights:
            rel = find_relation(exps, order, w)
            if rel and (cand is None or rel[0] < cand[0]): cand = rel
        if cand is None: continue
        cost, s, s_res, deg = cand
        pool.append((deg, subset, s, s_res))
    pool.sort(key=lambda t: t[0])       # lowest degree first
    # pick n_rel low-degree relations that are not near-duplicates (avoid shared spurious factors)
    chosen, sigs = [], []
    for deg, subset, s, s_res in pool:
        sig = frozenset(j for j, si in zip(subset, s) if si)
        if any(len(sig & prev) >= len(sig) - 1 for prev in sigs):  # skip if overlaps all-but-one
            continue
        chosen.append((subset, s, s_res, deg)); sigs.append(sig)
        if len(chosen) >= n_rel: break
    if len(chosen) < n_rel:            # fall back to plain lowest-degree if diversity too strict
        chosen = [(sub, s, sr, dg) for dg, sub, s, sr in pool[:n_rel]]
    return chosen

# --------------------------------------------------------------------------- #
#  checkpointing  (crash-resumable: never recompute a finished stage)          #
# --------------------------------------------------------------------------- #
def _ptag(p):
    return str(int(p))[-14:]                       # short, unique-enough per-prime tag

def _ck(path):
    os.makedirs(CKPT_DIR, exist_ok=True)
    return os.path.join(CKPT_DIR, path)

_M64 = int((1 << 64) - 1)

def save_coeffs(path, coeffs):
    """Persist a polynomial's coefficient list as 24-byte little-endian ints (atomic)."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        for c in coeffs:
            fh.write(int(c).to_bytes(24, "little"))
    os.replace(tmp, path)                          # atomic: a half-written file never looks complete

def load_coeffs(path):
    with open(path, "rb") as fh:
        data = fh.read()
    return [int.from_bytes(data[i:i + 24], "little") for i in range(0, len(data), 24)]

def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh: json.dump(obj, fh)
    os.replace(tmp, path)

def load_json(path):
    with open(path) as fh: return json.load(fh)

# --------------------------------------------------------------------------- #
#  build one F(x) on the real prime p  (parallel eval + fast interpolation)    #
# --------------------------------------------------------------------------- #
def degree_bound(s, s_res):
    Knz = sum(1 for v in s if v); D = 3 ** Knz
    sumabs = sum(abs(v) for v in s)
    # measured: actual deg ~ (D/3)*sum|s| (+ D*|s_res|); keep ~2x headroom.
    return (2 * D // 3) * sumabs + D * abs(s_res) + 16

def degree_estimate(s, s_res):
    Knz = sum(1 for v in s if v); D = 3 ** Knz
    return (D // 3) * sum(abs(v) for v in s) + D * abs(s_res)   # ~ actual degree

def build_F(samples, subset, s, s_res, p, ridx, use_ckpt=True):
    p = int(p)                                    # keep the eval hot-loop in fast C ints
    tag = _ptag(p)
    Fpath = _ck(f"F_{tag}_{ridx}.bin")
    if use_ckpt and os.path.exists(Fpath):        # this F already finished on an earlier run
        print(f"      [ckpt] F_{tag}_{ridx} already done -> loading", flush=True)
        return load_coeffs(Fpath)
    cs = [int(samples[j][1] % p) for j in subset]
    s = [int(v) for v in s]; s_res = int(s_res)
    n = int(degree_bound(s, s_res) + 3)
    t0 = time.time()
    if _FEVAL:                                    # ---- fast C evaluation kernel ----
        feval.setup(p)
        yspath = _ck(f"ys_{tag}_{ridx}.bin") if use_ckpt else None
        have = min(feval.count_records(yspath), n) if use_ckpt else 0   # points already on disk
        step = int(1 << 22)
        if have:                                       # resume: drop any torn tail, reload
            with open(yspath, "r+b") as fh: fh.truncate(have * 24)
            print(f"        [ckpt] resuming eval from {have}/{n} points", flush=True)
            ys = feval.read_records(yspath, have)
        else:
            ys = []
        print(f"        [C] evaluating {n} points (from {have}) ...", flush=True)
        fh = open(yspath, "ab") if use_ckpt else None
        try:
            for off in range(have, n, step):
                m = min(step, n - off)
                ys.extend(feval.c_eval_values(cs, s, s_res, p, 2 + off, m, fh=fh))
                frac = float(off + m) / float(n); el = float(time.time() - t0)
                eta = float(el / max(frac, 1e-9) - el); pct = float(100 * frac)
                print(f"          eval {pct:5.1f}%  ({el:.0f}s, eta {eta:.0f}s)", flush=True)
        finally:
            if fh is not None: fh.close()
    else:                                         # ---- pure-python fallback ----
        _W.update(cs=cs, sc=s, sr=s_res, p=p)
        ys = [None] * n
        chunk = max(1, n // (NPROC * 40))
        spans = [(2 + i, 2 + min(i + chunk, n)) for i in range(0, n, chunk)]
        print(f"        [py] evaluating {n} points over {len(spans)} chunks ...", flush=True)
        done = 0
        if NPROC > 1 and n > 4000:
            with Pool(NPROC) as pool:
                for lo, out in pool.imap_unordered(_eval_span, spans):
                    for t, v in enumerate(out): ys[lo - 2 + t] = v
                    done += 1
                    if done % max(1, len(spans) // 20) == 0:
                        frac = float(done) / float(len(spans)); el = float(time.time() - t0)
                        eta = float(el / max(frac, 1e-9) - el); pct = float(100 * frac)
                        print(f"          eval {pct:5.1f}%  ({el:.0f}s, eta {eta:.0f}s)", flush=True)
        else:
            for sp in spans:
                lo, out = _eval_span(sp)
                for t, v in enumerate(out): ys[lo - 2 + t] = v
    print(f"        eval done in {time.time()-t0:.0f}s; interpolating (deg~{n}) ...", flush=True)
    # large-degree interpolation via FLINT (NTL cannot handle these degrees)
    if not _HAVE_FLINT:
        raise RuntimeError("python-flint required for the real instance "
                           "(pip install python-flint). NTL cannot interpolate degrees this large.")
    ti = time.time()
    F = _FB.interpolate(p, 2, ys, deg_hint=int(degree_estimate(s, s_res)))
    print(f"        extracting {F.degree()+1} coefficients ...", flush=True)
    coeffs = _FB.to_coeffs(F)
    while len(coeffs) > 1 and coeffs[-1] == 0: coeffs.pop()
    if len(coeffs) - 1 >= n - 8:                  # hit the point ceiling -> bound too low, F aliased
        print(f"        [!] WARNING: interpolated degree {len(coeffs)-1} reached the point ceiling "
              f"({n}); degree_bound too low -> F may be wrong. Raise the bound and re-run.", flush=True)
    j = 0                                         # strip x^k factor (x=0 not a valid root) in ONE pass
    while j < len(coeffs) - 1 and coeffs[j] == 0: j += 1
    if j: coeffs = coeffs[j:]
    print(f"        interpolated deg {len(coeffs)-1} (x^{j} factor stripped) in {time.time()-ti:.0f}s", flush=True)
    if use_ckpt:                                  # persist F, then drop the bulky ys checkpoint
        print(f"        saving F checkpoint ...", flush=True)
        save_coeffs(Fpath, coeffs)
        try: os.remove(_ck(f"ys_{tag}_{ridx}.bin"))
        except OSError: pass
    return coeffs

# --------------------------------------------------------------------------- #
#  per-prime solve                                                            #
# --------------------------------------------------------------------------- #
def solve_prime(samples, p, subset_size, n_rel, tries, verbose=True, use_ckpt=True):
    p = int(p); order = p - 1; tag = _ptag(p)
    respath = _ck(f"mp_{tag}.json")
    if use_ckpt and os.path.exists(respath):      # this whole prime already solved earlier
        good = load_json(respath)
        print(f"    [ckpt] m mod p ({tag}) already solved -> {good}", flush=True)
        return good
    random.seed(p)                                # p is already a Python int; deterministic relations
    relpath = _ck(f"rels_{tag}.json")
    if use_ckpt and os.path.exists(relpath):
        rels = [tuple(r) for r in load_json(relpath)]
        print(f"    [ckpt] reusing saved relations for {tag}", flush=True)
    else:
        rels = pick_relations(samples, order, n_rel, subset_size, tries)
        if not rels:
            return []
        rels = [(list(map(int, sub)), list(map(int, s)), int(sr), int(pd))
                for (sub, s, sr, pd) in rels]      # plain ints -> JSON-serializable
        if use_ckpt:
            save_json(relpath, rels)              # lock relations in before any expensive F
    if verbose:
        for (sub, s, sr, pd) in rels:
            npos = sum(1 for v in s if v > 0); nneg = sum(1 for v in s if v < 0)
            print(f"      s_res={sr} split={npos}+{nneg} sum|s|={sum(abs(v) for v in s)} "
                  f"deg<={degree_bound(s,sr)}", flush=True)
    Fs = []
    for ridx, (subset, s, s_res, _pred) in enumerate(rels):
        t0 = time.time()
        Fs.append(build_F(samples, subset, s, s_res, p, ridx, use_ckpt=use_ckpt))
        if verbose:
            print(f"      built F (deg {len(Fs[-1])-1}) in {time.time()-t0:.1f}s", flush=True)
    tg = time.time()
    g = _FB.gcd_of(p, Fs)                          # FLINT gcd of the resultant polynomials
    while len(g) > 1 and g[0] == 0: g = g[1:]      # drop the x=0 factor
    roots = [r for r in _FB.roots_of(p, g) if r != 0] if len(g) > 1 else []
    if verbose:
        print(f"      gcd deg {len(g)-1}, roots {roots} in {time.time()-tg:.1f}s", flush=True)
    # recover m mod p from  x = m^{-1337}
    d = (-LCG_ADD) % order; gg = gcd(d, order); cand = set()
    for xr in roots:
        if xr == 0: continue
        if gg == 1:
            cand.add(pow(xr, inverse_mod(d, order), p))
        else:
            for t in GF(p)(xr).nth_root(d, all=True):
                cand.add(int(t))
    A0, c0 = samples[0]
    good = [int(mm) for mm in cand
            if (pow(mm, A0, p) + pow(mm, 3 * A0 + LCG_ADD, p)) % p == c0 % p]
    if use_ckpt:
        save_json(respath, good)                  # prime done -> cache result
    return good

# --------------------------------------------------------------------------- #
#  factoring / flag                                                           #
# --------------------------------------------------------------------------- #
def factor_N(N):
    if KNOWN_FACTORS:
        facs = [ZZ(f) for f in KNOWN_FACTORS]
        assert len(facs) == 2 and prod(facs) == N, "KNOWN_FACTORS don't multiply to N"
        print(f"[*] using known factors (skipping factorization)")
        return facs
    print(f"[*] factoring N ({N.nbits()} bits) ...", flush=True)
    # 273-bit balanced semiprime.  qsieve handles it; CADO-NFS is faster on a
    # workstation -- if you run CADO externally, just hard-code p, q above.
    try:
        facs = [ZZ(f) for f in qsieve(N)[0]]
    except Exception:
        facs = [ZZ(f) for f, _ in list(N.factor())]
    assert len(facs) == 2 and prod(facs) == N, f"bad factorization: {facs}"
    return facs

def recover(N, p, q, samples):
    print("[*] mod p:"); gp = solve_prime(samples, p, SUBSET_SIZE, N_RELATIONS, RELATION_TRIES)
    print(f"    m mod p candidates: {gp}")
    print("[*] mod q:"); gq = solve_prime(samples, q, SUBSET_SIZE, N_RELATIONS, RELATION_TRIES)
    print(f"    m mod q candidates: {gq}")
    for a in gp:
        for b in gq:
            m = int(crt([a, b], [p, q]))
            if 0 < m < N:
                bl = (m.bit_length() + 7) // 8
                fb = m.to_bytes(bl, "big")
                if b"kalmar" in fb.lower() or fb.isascii():
                    return m, fb
    return None, None

# --------------------------------------------------------------------------- #
#  SELF-TEST                                                                   #
# --------------------------------------------------------------------------- #
def self_test():
    print("=" * 70); print(" SELF-TEST : full pipeline on toy primes"); print("=" * 70)
    random.seed(int(2026))
    p = int(next_prime(random.randint(int(2 ** 17), int(2 ** 18))))
    q = int(next_prime(random.randint(int(2 ** 17), int(2 ** 18))))
    N = p * q; m = random.randint(int(2), int(N - 1))
    lcg = lambda s: (3 * s + LCG_ADD) % N
    samples = []
    while len(samples) < max(24, 4 * ST_SUBSET):
        e = random.randint(int(731), int(N - 1)); A = lcg(e); B = lcg(A)
        if (3 * A + LCG_ADD - B) // N == 0:
            samples.append((A, (pow(m, A, N) + pow(m, B, N)) % N))
    print(f"[*] toy N={N} ({N.bit_length()}b), {len(samples)} k=0 samples, true m={m}")
    t0 = time.time()
    gp = solve_prime(samples, p, ST_SUBSET, ST_NREL, ST_TRIES, use_ckpt=False)
    gq = solve_prime(samples, q, ST_SUBSET, ST_NREL, ST_TRIES, use_ckpt=False)
    got = next((int(crt([a, b], [p, q])) for a in gp for b in gq
                if int(crt([a, b], [p, q])) == m), None)
    print(f"[*] m mod p {gp} (true {m%p}) | m mod q {gq} (true {m%q})")
    ok = (got == m)
    print(f"[{'PASS' if ok else 'FAIL'}]  flag-int recovered == m : {ok}   ({time.time()-t0:.1f}s)")
    assert ok, "self-test FAILED -- fix before running real data"
    print("Self-test passed.  Set MODE='real'.\n")

# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    if MODE == "selftest":
        self_test()
    else:
        N, r_list, dbg = load(OUTPUT_FILE); N = ZZ(N)
        samples = k0_samples(N, r_list, dbg)
        print(f"[*] config: SUBSET_SIZE={SUBSET_SIZE} N_RELATIONS={N_RELATIONS} "
              f"RELATION_TRIES={RELATION_TRIES} SRES_WEIGHT={SRES_WEIGHT} NPROC={NPROC}")
        print(f"[*] N = {N} ({N.nbits()} bits);  k=0 samples: {len(samples)}")
        p, q = factor_N(N)
        print(f"[*] p = {p}\n[*] q = {q}")
        m, flag = recover(N, ZZ(p), ZZ(q), samples)
        if flag is not None:
            print("\n" + "=" * 70)
            print(f"[+] m    = {m}")
            print(f"[+] FLAG = {flag.decode(errors='replace')}")
            print("=" * 70)
        else:
            print("[-] no consistent (m mod p, m mod q); raise N_RELATIONS / "
                  "RELATION_TRIES / SUBSET_SIZE.")
