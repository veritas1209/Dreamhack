from Crypto.Cipher import AES as _A
from Crypto.Util.Padding import pad as _P
from random import seed as _s, shuffle as _h

# _K = ???
P = b"0123456789abcdef"
# The report contains 1024 bytes of 'A' right after the header and P.

def _x(_k):
    _s(int.from_bytes(_k, 'big'))
    _l = list(range(0x10))
    _h(_l)
    return _l

def _y(_c, _k):
    return _A.new(_k, _A.MODE_ECB).encrypt((0).to_bytes(8, 'big') + _c.to_bytes(8, 'big'))

def enc(_m):
    _m = _P(_m, 0x10)
    _o, _p = b"", b"\x00" * 0x10
    _t = _x(_K)
    for _i in range(0, len(_m), 0x10):
        _b = bytes([_m[_i:_i+0x10][_j] for _j in _t])
        _k = _y((_i // 0x10) % 0x10, _K)
        _p = bytes([_a ^ _b ^ _c for _a, _b, _c in zip(_b, _k, _p)])
        _o += _p
    return _o