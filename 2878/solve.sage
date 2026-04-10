import os, struct, subprocess, hashlib, sys, operator
from pwn import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- [ Math & Cryptography Helpers ] ---
P = 0x1ffffffffffffcc3
B_MAIN, B_SUB = 0x17afbb6c15c8131c, P - 0x17afbb6c15c8131c
D_MAIN, D_SUB = 0xa85fb6bf0889, 0xc9303cd705ea

def mod_inv(a, p): return pow(a, p - 2, p)
def curve_eval(x, b, p): return (pow(x, 3, p) - (3 * x) % p + b) % p
def tonelli_shanks(n, p):
    if pow(n, (p - 1) // 2, p) != 1: return None
    q, s = p - 1, 0
    while q % 2 == 0: q //= 2; s += 1
    if s == 1: return pow(n, (p + 1) // 4, p)
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1: z += 1
    c, r, t, m = pow(z, q, p), pow(n, (q + 1) // 2, p), pow(n, q, p), s
    while t != 1:
        i, tmp = 0, t
        while tmp != 1 and i < m: tmp = pow(tmp, 2, p); i += 1
        if i == m: return None
        b_val = pow(c, 1 << (m - i - 1), p)
        r, t, c, m = (r * b_val) % p, (t * b_val * b_val) % p, (b_val * b_val) % p, i
    return r

def point_add(p1, p2, p):
    if not p1: return p2
    if not p2: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and y1 != y2: return None
    if x1 == x2: num, den = (3 * x1 * x1 - 3) % p, mod_inv(2 * y1, p)
    else: num, den = (y2 - y1) % p, mod_inv(x2 - x1, p)
    slope = (num * den) % p; x3 = (slope * slope - x1 - x2) % p
    return (x3, (slope * (x1 - x3) - y1) % p)

def point_mul(k, pt, p):
    res, addend = None, pt
    while k > 0:
        if k & 1: res = point_add(res, addend, p)
        addend = point_add(addend, addend, p); k >>= 1
    return res

def get_next_state(out_x, a, b):
    curve_B, d_val = (B_MAIN if b == 0 else B_SUB), (D_MAIN if a == 0 else D_SUB)
    y = tonelli_shanks(curve_eval(out_x, curve_B, P), P)
    if y is None: return
    for test_y in (y, P - y):
        next_pt = point_mul(d_val, (out_x, test_y), P)
        if next_pt: yield next_pt[0]

class ClonePRNG:
    def __init__(self, state): self.state, self.bit_pool, self.bits_left = state, 0, 0
    def raw_block(self):
        a, b = self.state & 1, (self.state >> 1) & 1
        P_pt = (0x12ffa4d01fc24c2f, 0x0f0a2b484d7feee5) if a == 0 else (0x1056b54e26659737, 0x0d9bf470518ea602)
        Q_pt = (0x05d02f2d52087ca6, 0x0351d5364f309abd) if b == 0 else (0x180c69fc0875d5a3, 0x07297c426a993c63)
        out_pt = point_mul(self.state, Q_pt, P)
        self.state = point_mul(self.state, P_pt, P)[0]
        if self.state == 0: self.state = 1
        return out_pt[0]
    def random_bits(self, bits):
        res, produced = 0, 0
        while produced < bits:
            if self.bits_left == 0: self.bit_pool, self.bits_left = self.raw_block(), 61
            take = min(bits - produced, self.bits_left)
            res |= ((self.bit_pool & ((1 << take) - 1)) << produced)
            self.bit_pool >>= take; self.bits_left -= take; produced += take
        return res
    def random_bytes(self, n): return bytes(self.random_bits(8) for _ in range(n))

def normalize_key(key): return key if len(key) == 32 else hashlib.sha256(key).digest()
def aes_crypt(data, key, mode_func):
    cipher = Cipher(algorithms.AES(normalize_key(key)), modes.CBC(b'\x00'*16), backend=default_backend())
    worker = mode_func(cipher)
    return worker.update(data) + worker.finalize()

def recv_pkt(r, key, desc=""):
    print(f"    [NET-RECV] Waiting for: {desc}...")
    length = struct.unpack('>I', r.recvn(4))[0]
    pt = aes_crypt(r.recvn(length), key, lambda c: c.decryptor()).decode()
    snippet = pt.strip().replace('\n', ' | ')
    if len(snippet) > 60: snippet = snippet[:57] + "..."
    print(f"    [NET-RECV] Data: {snippet}")
    return pt[:-1] if pt.endswith('\x00') else pt

def send_pkt(r, key, msg, desc=""):
    print(f"    [NET-SEND] Task: {desc} (Data: '{msg}')")
    pt = msg.encode()
    pad = 16 - (len(pt) % 16); pt += bytes([pad] * pad)
    ct = aes_crypt(pt, key, lambda c: c.encryptor())
    r.send(struct.pack('>I', len(ct)) + ct)

def sample_in_ball(seed):
    print("      [MATH] Generating SampleInBall...")
    c = [0] * 256
    h = hashlib.shake_256(seed).digest(256)
    signs = int.from_bytes(h[:8], 'little')
    pos = 8
    for i in range(256 - 39, 256):
        while True:
            if pos >= len(h): h = hashlib.shake_256(seed).digest(len(h) * 2)
            b = h[pos]; pos += 1
            if b <= i: break
        c[i] = c[b]; c[b] = 1 if (signs & 1) == 0 else -1; signs >>= 1
    return c

def fast_inverse(poly_list):
    print("      [MATH] Hensel Lifting (GF(2) -> Z_16)...")
    R2 = PolynomialRing(GF(2), 'x'); x2 = R2.gen()
    inv2 = R2(poly_list).inverse_mod(x2**256 + 1)
    R16 = PolynomialRing(Zmod(16), 'x'); x16 = R16.gen()
    f, g, mod_poly = R16(poly_list), R16(inv2.list()), x16**256 + 1
    g = (g * (2 - f * g)) % mod_poly 
    g = (g * (2 - f * g)) % mod_poly 
    return g

def bytes_to_coeffs(data):
    res = []
    for b in data: res.append(b & 0x0f); res.append(b >> 4)
    return res

def coeffs_to_bytes(coeffs):
    res = []
    for i in range(0, 256, 2): res.append((coeffs[i] & 0x0f) | ((coeffs[i+1] & 0x0f) << 4))
    return bytes(res)

# --- [ Exploit Execution ] ---
def main():
    context.log_level = 'error'
    print("\n========================================")
    print(" [STAGE 1] Syncing PRNG & ML-KEM AES")
    print("========================================")
    r = remote('host3.dreamhack.games', 20163)
    r.recvuntil(b"handshake.\n"); r.sendline(b"START"); r.recvline()
    
    trace = r.recvn(struct.unpack('>I', r.recvn(4))[0])
    b0, b1 = struct.unpack('<Q', trace[:8])[0], struct.unpack('<Q', trace[8:16])[0]
    
    found_state = next(st for b in (0,1) for a in (0,1) for st in get_next_state(b0, a, b) 
                       if st != 0 and list(get_next_state(b1, st&1, (st>>1)&1)))
    print(f"[*] State Recovered: {hex(found_state)}")
    prng = ClonePRNG(found_state)
    for _ in range(7): prng.raw_block()
    
    pk = r.recvn(struct.unpack('>I', r.recvn(4))[0]); prng.random_bytes(64)
    p = subprocess.Popen(['./kem_helper'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out, _ = p.communicate(pk); r.send(struct.pack('>I', 768) + out[:768]); session_key = out[768:]
    print("[*] Secure Session Established!")

    print("\n========================================")
    print(" [STAGE 2] Register & Login")
    print("========================================")
    for _ in range(2): recv_pkt(r, session_key, "Init Flush")
    send_pkt(r, session_key, "1", "Reg"); recv_pkt(r, session_key, "Pmt"); send_pkt(r, session_key, "a", "ID")
    recv_pkt(r, session_key, "Pmt"); send_pkt(r, session_key, "a", "PW")
    for _ in range(2): recv_pkt(r, session_key, "Menu Flush")
    
    send_pkt(r, session_key, "2", "Log"); recv_pkt(r, session_key, "Pmt"); send_pkt(r, session_key, "a", "ID")
    recv_pkt(r, session_key, "Pmt"); send_pkt(r, session_key, "a", "PW")
    recv_pkt(r, session_key, "Welcome"); recv_pkt(r, session_key, "Menu")

    print("\n========================================")
    print(" [STAGE 3] Harvesting & Inverting t0")
    print("========================================")
    t0_mod_16_all = []
    for lane in range(4):
        send_pkt(r, session_key, "7", f"Quote L{lane}"); recv_pkt(r, session_key, "Pmt")
        send_pkt(r, session_key, "0", "Room"); recv_pkt(r, session_key, "Pmt"); send_pkt(r, session_key, "00", "Data")
        resp = recv_pkt(r, session_key, "Quote Data"); recv_pkt(r, session_key, "Menu")
        
        sig_hex = next(l.split(":")[-1].strip() for l in resp.split('\n') if len(l.split(":")[-1].strip()) == 4840)
        ref_hex = next(l.split(":")[-1].strip() for l in resp.split('\n') if len(l.split(":")[-1].strip()) == 256)
        
        prng.random_bytes(32); mask = prng.random_bytes(128)
        pure_code = bytes(operator.xor(a, b) for a, b in zip(bytes.fromhex(ref_hex), mask))
        
        poly_c_inv = fast_inverse(sample_in_ball(bytes.fromhex(sig_hex)[:32]))
        poly_code = PolynomialRing(Zmod(16), 'x')(list(bytes_to_coeffs(pure_code)))
        recovered = (poly_c_inv * poly_code) % (PolynomialRing(Zmod(16), 'x').gen()**256 + 1)
        
        t0_mod_16_all.append([int(c) for c in recovered.list()])
        print(f"    [+] Lane {lane} Extracted!")

    print("\n========================================")
    print(" [STAGE 4] Forging ML-DSA Signature")
    print("========================================")
    send_pkt(r, session_key, "9", "Get PK"); pk_resp = recv_pkt(r, session_key, "PK Data")
    recv_pkt(r, session_key, "Menu")
    pk_hex = next(l.split(":")[-1].strip() for l in pk_resp.split('\n') if "pk(hex):" in l)

    with open("secret_t0.bin", "wb") as f:
        for lane in t0_mod_16_all: f.write(coeffs_to_bytes(lane))
    
    print("[*] Running forge_helper.cpp (LWE Overwrite)...")
    p = subprocess.Popen(['./forge_helper'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    forged_sig, _ = p.communicate(bytes.fromhex(pk_hex))

    print("\n========================================")
    print(" [STAGE 5] Profit & Get Flag")
    print("========================================")
    send_pkt(r, session_key, "8", "Redeem Menu"); recv_pkt(r, session_key, "Pmt")
    send_pkt(r, session_key, b"VOUCHER 500000 1337".hex(), "Msg Hex"); recv_pkt(r, session_key, "Pmt")
    send_pkt(r, session_key, forged_sig.hex(), "Sig Hex")
    
    res = recv_pkt(r, session_key, "Result")
    print(f"\n[!] SERVER: {res.strip()}")
    
    if "redeemed" in res or "505000" in res:
        print("\n[+] SUCCESS! Booking 100 rooms...")
        recv_pkt(r, session_key, "Menu")
        for i in range(100):
            sys.stdout.write(f"\r    -> Booking Room {i}/99..."); sys.stdout.flush()
            send_pkt(r, session_key, "4", "Reserve"); recv_pkt(r, session_key, "Pmt")
            send_pkt(r, session_key, str(i), "ID"); recv_pkt(r, session_key, "Res Result")
            recv_pkt(r, session_key, "Menu")
        
        print("\n\n[*] All rooms booked. Requesting Flag!")
        send_pkt(r, session_key, "10", "Flag")
        flag_resp = recv_pkt(r, session_key, "Flag Output")
        print(f"\n🚩 FLAG: {flag_resp.strip()}")
    r.close()

if __name__ == '__main__':
    main()