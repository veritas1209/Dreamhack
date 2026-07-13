"""Large-degree polynomial back-end over GF(p) using python-flint.

Sage's GF(p)[x] for a 137-bit prime uses NTL, whose FFT caps out around degree
2**25 (~33.5M) -> "Polynomial too big for FFT".  Our resultant polynomials reach
50M-100M, so the interpolation and gcd are done here with FLINT instead
(fmpz_mod_poly: Kronecker/FFT multiplication with no such ceiling).

Requires:  pip install python-flint   (>= 0.6; tested on 0.9.0)

interpolate() uses the closed form of M'(x_i) for CONSECUTIVE integer points
(no down-tree needed) and a subproduct-tree up-combine.
"""
import flint
import os
import time

# FLINT can multithread its (large) polynomial multiplications.  Default is 1;
# raise it so the interpolation/gcd use all cores.  Override with FLINT_THREADS.
_NTHREADS = int(os.environ.get("FLINT_THREADS", os.cpu_count() or 1))
try:
    flint.ctx.threads = _NTHREADS
except Exception:
    pass


def _ctx(p):
    return flint.fmpz_mod_poly_ctx(int(p))


def interpolate(p, lo, ys, deg_hint=None, verbose=True):
    """Interpolate the polynomial through (lo+i, ys[i]) for i in range(len(ys)).

    deg_hint: optional estimate of the true degree; if given we interpolate with
    only ~1.25*deg_hint points and verify against held-out points, which avoids
    paying for the (deliberately loose) evaluation bound.  Falls back to using
    all points if the short interpolation fails to reproduce the held-out values.
    Returns a flint fmpz_mod_poly.
    """
    p = int(p); lo = int(lo); N = len(ys)
    ctx = _ctx(p)

    def _interp(n):
        t0 = time.time()
        if verbose:
            print(f"          [flint] interpolating {n} points, threads={_NTHREADS}", flush=True)
        # c_i = ys[i] / M'(x_i),  M'(x_i) = (-1)^{n-1-i} * i! * (n-1-i)!
        fact = [1] * n
        for i in range(1, n):
            fact[i] = fact[i - 1] * i % p
        invf = [0] * n
        invf[n - 1] = pow(fact[n - 1], p - 2, p)
        for i in range(n - 1, 0, -1):
            invf[i - 1] = invf[i] * i % p
        P = [ctx([(-((lo + i) % p)) % p, 1]) for i in range(n)]
        C = []
        for i in range(n):
            mp = invf[i] * invf[n - 1 - i] % p
            if (n - 1 - i) & 1:
                mp = p - mp
            C.append(ctx([int(ys[i]) * mp % p]))
        level = 0
        while len(P) > 1:
            if verbose:
                print(f"          [flint] combine level {level}: {len(P)} nodes "
                      f"(deg~{P[0].degree()})  {time.time()-t0:.0f}s", flush=True)
            nP, nC = [], []
            for i in range(0, len(P), 2):
                if i + 1 < len(P):
                    nP.append(P[i] * P[i + 1])
                    nC.append(C[i] * P[i + 1] + C[i + 1] * P[i])
                else:
                    nP.append(P[i]); nC.append(C[i])
            P, C = nP, nC
            level += 1
        if verbose:
            print(f"          [flint] interpolation done in {time.time()-t0:.0f}s", flush=True)
        return C[0]

    if deg_hint is not None and int(deg_hint) * 5 // 4 + 16 < N:
        n = int(deg_hint) * 5 // 4 + 16
        F = _interp(n)
        # verify at up to 8 held-out points beyond the ones used
        ok = True
        checks = [n + k for k in range(0, N - n, max(1, (N - n) // 8))][:8]
        for j in checks:
            if int(F.evaluate(flint.fmpz((lo + j) % p))) != int(ys[j]) % p:
                ok = False; break
        if ok:
            return F
        # else: hint too low, fall through to full interpolation
    return _interp(N)


def to_coeffs(F):
    return [int(c) for c in F.coeffs()]


def poly_from_coeffs(p, coeffs):
    return _ctx(p)([int(c) for c in coeffs])


def gcd_of(p, coeff_lists, verbose=True):
    """gcd of several polynomials (each given as an int coefficient list)."""
    ctx = _ctx(p)
    polys = [ctx([int(c) for c in cl]) for cl in coeff_lists]
    g = polys[0]
    for h in polys[1:]:
        t0 = time.time()
        g = g.gcd(h)
        if verbose:
            print(f"          [flint] gcd -> deg {g.degree()}  ({time.time()-t0:.0f}s)", flush=True)
    return [int(c) for c in g.coeffs()]


def roots_of(p, coeffs):
    """Distinct roots (as ints) of the polynomial given by its coefficient list."""
    ctx = _ctx(p)
    g = ctx([int(c) for c in coeffs])
    return [int(r) for (r, _m) in g.roots()]
