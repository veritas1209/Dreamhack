"""ctypes wrapper around feval.so (the C evaluation kernel).

Build the shared library first:
    gcc -O3 -march=native -fopenmp -shared -fPIC -o libfeval.so feval.c

Then solve.sage imports this module and uses c_eval_values() to evaluate F(x)
over a range of consecutive integer x, using all OpenMP threads inside C.

If feval.so is missing, `available` is False and solve.sage falls back to the
pure-python evaluator.
"""
import os, ctypes

_HERE = os.path.dirname(os.path.abspath(__file__))
_SO = os.path.join(_HERE, "libfeval.so")

available = False
_lib = None


def _load():
    global _lib, available
    if _lib is not None:
        return available
    if not os.path.exists(_SO):
        available = False
        return False
    lib = ctypes.CDLL(_SO)
    u64 = ctypes.c_uint64
    P = ctypes.POINTER
    lib.feval_setup.argtypes = [P(u64), P(u64), P(u64), u64]
    lib.feval_setup.restype = None
    lib.feval_range.argtypes = [u64, u64, P(u64), P(ctypes.c_long),
                                ctypes.c_int, ctypes.c_long, u64, P(u64)]
    lib.feval_range.restype = None
    _lib = lib
    available = True
    return True


def _limbs(v):
    return [(v >> (64 * i)) & ((1 << 64) - 1) for i in range(3)]


def _arr(vals, typ=ctypes.c_uint64):
    return (typ * len(vals))(*vals)


def setup(p):
    """Load the modulus p into the C kernel (call once per prime)."""
    _load()
    p = int(p)
    np = (-pow(p, -1, 1 << 64)) % (1 << 64)
    r2 = _limbs(((1 << 192) ** 2) % p)
    pm2 = _limbs(p - 2)
    _lib.feval_setup(_arr(_limbs(p)), _arr(r2), _arr(pm2), ctypes.c_uint64(np))


def c_eval_values(cs, s, s_res, p, lo, n, chunk=1 << 22, fh=None):
    """Return [F(x) for x in range(lo, lo+n)] as ordinary ints mod p.

    cs    : list of c_i (ints)          -- one per nonzero-support factor, in subset order
    s     : list of signed exponents    -- same length as cs
    s_res : the relation's x-exponent
    p     : prime (setup(p) must have been called)
    lo, n : evaluate x = lo .. lo+n-1
    chunk : points per C call (bounds the output buffer size)
    fh    : optional open binary file; each chunk's raw 3x u64 limbs are written
            to it (for crash-resumable checkpointing) before being returned.
    """
    _load()
    p = int(p); lo = int(lo); n = int(n); chunk = int(chunk); s_res = int(s_res)
    cs_limbs = []
    for c in cs:
        cs_limbs += _limbs(int(c) % p)
    cs_arr = _arr(cs_limbs)
    s_arr = _arr([int(v) for v in s], ctypes.c_long)
    nit = ctypes.c_int(len(cs))
    sres = ctypes.c_long(int(s_res))
    order_lo = ctypes.c_uint64((p - 1) & ((1 << 64) - 1))
    u64 = ctypes.c_uint64

    out = []
    x = lo
    end = lo + n
    while x < end:
        m = min(chunk, end - x)
        buf = (u64 * (m * 3))()
        _lib.feval_range(u64(x), u64(x + m), cs_arr, s_arr, nit, sres,
                         order_lo, buf)
        if fh is not None:                       # checkpoint: raw limbs to disk, then flush
            fh.write(bytes(buf)); fh.flush(); os.fsync(fh.fileno())
        for i in range(m):
            out.append(buf[i * 3] | (buf[i * 3 + 1] << 64) | (buf[i * 3 + 2] << 128))
        x += m
    return out


def read_records(path, count):
    """Read `count` values (3x little-endian u64 = 24 bytes each) back as ints."""
    import struct
    out = []
    with open(path, "rb") as fh:
        data = fh.read(count * 24)
    for a, b, c in struct.iter_unpack("<QQQ", data):
        out.append(a | (b << 64) | (c << 128))
    return out


def count_records(path):
    """Number of complete 24-byte records already on disk (partial tail ignored)."""
    try:
        return os.path.getsize(path) // 24
    except OSError:
        return 0
