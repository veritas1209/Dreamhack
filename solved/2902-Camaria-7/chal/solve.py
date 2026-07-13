"""
Camaria block-cipher model and per-block key recovery.

The encryptor is CBC over a "block cipher" E that is a DOUBLE 12-round ARIA-128:
    C = ARIA2( ARIA1( P xor C_prev ) )
The per-block round keys depend ONLY on the previous ciphertext block C_prev
(position-independent), so block i's cipher is E_{f(C_{i-1})}.

Block 1 (C_prev = C0 = the fixed file header) is fully recovered (keys embedded
below).  For block i>=2 we recover the cipher keyed by C_{i-1} by encrypting a
crafted 2-user-block file whose first ciphertext block equals C_{i-1}
(achieved with P1 = D1(C_{i-1}) xor C0), tracing its S-box accesses, and peeling
the two 12-round ARIA runs.
"""
import aria

X   = lambda p, q: bytes(a ^ b for a, b in zip(p, q))
A   = aria.A
SL  = lambda t, v: aria.SL1(v) if t == 'A' else aria.SL2(v)
SLi = lambda t, v: aria.SL2(v) if t == 'A' else aria.SL1(v)   # inverse substitution

C0 = bytes.fromhex('cc7f688734e770dec3140142ffae82ab')        # file header = C_0

# ---- Block-1 cipher round keys (C_prev = C0), recovered & verified ----
_EK1 = [bytes.fromhex(h) for h in [
 'e7fff8c6ebd65b94cbff24dc0145c0b6','b5dd5ac5f426e8b659a87c2ea0815823',
 '3e707e965486be8f0edc2b3bdeeec02c','2274ee75009959922e0079da78f37975',
 '144409d59e33e3b1f016de0aa80179ee','0aa0f2f86d769d215dd0d0a2082d95ca',
 '432f2d8445dd6bae8c95a8a4dcf01501','0fc2ad904e5c1bd985daf0f134cc65cd',
 'afe6210cbbce118ea0a31e2cbf2fa4a1','b27c204308f0ef3c8d400775c80c1966',
 'ff0c385efc7a9933a44d10ecb4a733d7','4f9f3f12449076fd30ce52d6c64c25e2']]
_EK2 = [None] + [bytes.fromhex(h) for h in [
 'f07060b55a2a3626983fb132fa4f0b98','cb12a7171073babcbfa5519a691a03eb',
 'f7374f0b6c91bd2327dae946e2e0b62e','40ab870681306e4102f31a15bf398f85',
 '671ddf6b4280c6ca661487c9f2078966','c04c747df616f6621c13b8110e522acd',
 'f9b8405e9643d4ac9e6947efdd5e74fd','feaf9cecde95217db94032f8902bda48',
 'b0f2df083ba8498023a1268a79634589','ac716509fede17e61ad30911ca36bbb0',
 'f9b1978ddcfbdc858b5675f47ff81cc4','c71915369d2a9d2dd7009b34ca9db195']]
_KB = bytes.fromhex('4c0754b9a5edc1bd6e2b90d79aeb3cca')

def make_enc(ek1, ek2, KB):
    """Forward double-ARIA block cipher (24 substitution layers, merged boundary)."""
    def E(P):
        s = P
        for i in range(11): s = A(SL('A' if i % 2 == 0 else 'B', X(s, ek1[i])))
        s = SL('B', X(s, ek1[11]))            # stage-1 final substitution
        s = A(SL('A', X(s, KB)))              # stage-2 round 1 (merged key KB)
        for i in range(1, 11): s = A(SL('A' if i % 2 == 0 else 'B', X(s, ek2[i])))
        s = SL('B', X(s, ek2[11])); s = X(s, ek2[12])
        return s
    return E

def make_dec(ek1, ek2, KB):
    """Inverse of make_enc."""
    def D(C):
        s = C
        s = X(s, ek2[12]); s = X(SLi('B', s), ek2[11])
        for i in range(10, 0, -1):
            s = X(SLi('A' if i % 2 == 0 else 'B', A(s)), ek2[i])
        s = X(SLi('A', A(s)), KB); s = X(SLi('B', s), ek1[11])
        for i in range(10, -1, -1):
            s = X(SLi('A' if i % 2 == 0 else 'B', A(s)), ek1[i])
        return s
    return D

D1 = make_dec(_EK1, _EK2, _KB)   # block-1 decryptor (C_prev = C0)
E1 = make_enc(_EK1, _EK2, _KB)   # block-1 encryptor

def _groups(acc):
    g = []
    tag = {'SB1':'1','SB2':'2','SB3':'3','SB4':'4'}
    for k in range(len(acc)//16):
        idx = bytes(acc[k*16+j][1] for j in range(16))
        sig = ''.join(tag[acc[k*16+j][0]] for j in range(16))
        if   sig == '1234123412341234': t = 'A'
        elif sig == '3412341234123412': t = 'B'
        else: t = '?'
        g.append((t, idx))
    return g

def _peel(i1, i2, X2, C2):
    """Given the two runs' substitution-input groups and (X2 -> C2), build keys."""
    s = X2; ek1 = [None]*12
    for i in range(11):
        ek1[i] = X(s, i1[i]); s = A(SL('A' if i % 2 == 0 else 'B', i1[i]))
    ek1[11] = X(s, i1[11])
    KB = X(aria.SL2(i1[11]), i2[0])
    ek2 = [None]*13; v = A(aria.SL1(i2[0]))
    for i in range(1, 11):
        ek2[i] = X(v, i2[i]); v = A(SL('A' if i % 2 == 0 else 'B', i2[i]))
    ek2[11] = X(v, i2[11]); ek2[12] = X(C2, aria.SL2(i2[11]))
    return ek1, ek2, KB

def recover_cipher(acc, X2, C2, X2b=None, C2b=None):
    """
    Recover the double-ARIA round keys for the (block-2) encryption captured in
    `acc`, given the known ARIA input X2 and output C2.  If an independent
    oracle point (X2b, C2b) is supplied it is used to validate the recovery
    (protects against run-position drift).  Returns (ek1, ek2, KB) or None.
    """
    g = _groups(acc); ng = len(g)
    starts = [i for i in range(ng-12)
              if [g[i+k][0] for k in range(12)] == list('ABABABABABAB')]
    # Try the canonical run positions first, then fall back to a full search.
    ordered = []
    if 1335 in starts: ordered.append(1335)
    ordered += [s for s in starts if s != 1335]
    for a_ in ordered:
        i1 = [g[a_+k][1] for k in range(12)]
        for b_ in starts:
            if b_ <= a_+11 or b_ > a_+700: continue
            i2 = [g[b_+k][1] for k in range(12)]
            ek1, ek2, KB = _peel(i1, i2, X2, C2)
            E = make_enc(ek1, ek2, KB)
            if E(X2) != C2: continue
            if X2b is not None and E(X2b) != C2b: continue   # 2-point validation
            return ek1, ek2, KB
    return None
