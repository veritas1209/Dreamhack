#!/usr/bin/env sage
# Schnorsa 풀이 (SageMath)
#
# 사용법:
#   원격 공격:   sage solve.sage HOST PORT
#   로컬 검증:   sage solve.sage --selftest 100
#
# 핵심 취약점 2가지
#   (1) pub() 가 phi 를 그대로 노출 -> 서명식 s = k + x*r (mod phi) 의 modulus 를 알게 됨.
#   (2) get_nonce() 가 시드 nk 하나로부터 완전 결정적(추가 난수 X)으로 논스를 생성.
#       k_{i+1} = k_i*2^64 - a_i*2^1024 + x_i,  a_i,x_i ∈ [0,2^64)
#       이 정수 관계 + (1) 을 합치면 x 에 대한 4미지수(<2^64) 모듈러 방정식이 나오고
#       LLL 로 작은 해를 복원 -> x 를 phi 기준으로 유일 결정할 수 있음.

import sys, socket, re, random
from sage.all import Matrix, ZZ

P64   = 1 << 64
P1024 = 1 << 1024
NB    = 1024
E     = 0x10001

# ----------------------------------------------------------------------
# 1) 작은 미지수 복원용 모듈러 선형방정식 솔버 (Kannan 임베딩 + LLL)
#    sum coeffs[i]*u_i + C ≡ 0 (mod phi),  0 <= u_i < bound  를 만족하는 u 반환
# ----------------------------------------------------------------------
def solve_modeq(coeffs, C, phi, bound, Kexp=220):
    m    = len(coeffs)
    half = bound // 2
    Cc   = (C + sum(coeffs) * half) % phi          # 변수 중앙화
    K    = 1 << Kexp                               # 마지막 열(모듈러 항)에 큰 가중치
    dim  = m + 2
    M = [[0] * dim for _ in range(dim)]
    for i in range(m):
        M[i][i]       = 1
        M[i][dim - 1] = coeffs[i] * K
    M[m][m]       = bound                          # 상수항 변수(=±bound)
    M[m][dim - 1] = Cc * K
    M[m + 1][dim - 1] = phi * K                    # 모듈러 행
    B = Matrix(ZZ, M).LLL()
    for row in B.rows():
        if row[dim - 1] != 0:
            continue
        wcol = row[m]
        if abs(wcol) != bound:
            continue
        sgn = 1 if wcol == bound else -1
        v = [sgn * int(row[i]) for i in range(m)]
        u = [vi + half for vi in v]
        if all(0 <= ui < bound for ui in u) and \
           (sum(coeffs[i] * u[i] for i in range(m)) + C) % phi == 0:
            return u
    return None

# ----------------------------------------------------------------------
# 2) 보조 정수론
# ----------------------------------------------------------------------
def gcd(a, b):
    a, b = int(a), int(b)
    while b:
        a, b = b, a % b
    return a

def egcd(a, b):
    a, b = int(a), int(b)
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def modinv(a, m):
    a, m = int(a) % int(m), int(m)
    g, x, _ = egcd(a, m)
    if g != 1:
        return None
    return x % m

def lin_congruence(A, R, m):
    A, R, m = int(A), int(R), int(m)
    g = gcd(A, m)
    if R % g != 0:
        return None
    mm = m // g
    inv = modinv((A // g) % mm, mm)
    if inv is None:
        return None
    return ((((R // g) % mm) * inv) % mm, mm)

def crt(r1, m1, r2, m2):
    r1, m1, r2, m2 = int(r1), int(m1), int(r2), int(m2)
    g = gcd(m1, m2)
    if (r2 - r1) % g != 0:
        return None
    lcm = m1 // g * m2
    inv = modinv((m1 // g) % (m2 // g), m2 // g)
    if inv is None:
        return None
    return ((r1 + ((r2 - r1) // g * inv % (m2 // g)) * m1) % lcm, lcm)

# 후보 x 의 결정적 검증: 논스 k_i 복원 -> t_i=2^{k_i} -> r 관계식이 실제 r_i 와 일치?
def verify_x(x, rs, ss, msgs, e, n, phi):
    for i in range(len(rs)):
        v = (ss[i] - x * rs[i]) % phi
        j = 0; ok = False
        while v + j * phi < P1024:          # 논스는 1024비트, phi 는 1023비트일 수 있어 j=0..3
            k = v + j * phi
            t = pow(2, k, n)
            if pow((t << NB) | msgs[i], e, n) == rs[i]:
                ok = True; break
            j += 1
        if not ok:
            return False
    return True

# ----------------------------------------------------------------------
# 3) 메인 공격: 4개의 서명으로 x 후보(생존자) 집합을 반환
#    - 정확히 1명만 생존하면 그 값이 100% 진짜 x (mod=phi, 유일).
#    - 2명 이상이면 (서명 transcript 로 구분 불가능한 충돌) -> 재접속 필요.
# ----------------------------------------------------------------------
def attack(pub, sigs, msgs):
    e, phi, n, y = pub
    rs = [s[0] for s in sigs]
    ss = [s[1] for s in sigs]
    A  = [(rs[i] * P64 - rs[i + 1]) % phi for i in range(len(sigs) - 1)]
    Bv = [(ss[i + 1] - ss[i] * P64) % phi for i in range(len(sigs) - 1)]

    # (a) 연속한 두 방정식에서 x 를 소거 -> 4미지수(a_i,x_i,a_{i+1},x_{i+1}) 모듈러식 -> LLL
    small = {}
    for i in range(len(A) - 1):
        A0, B0, A1, B1 = A[i], Bv[i], A[i + 1], Bv[i + 1]
        c0 = (A1 * P1024) % phi
        c1 = (-A1) % phi
        c2 = (-A0 * P1024) % phi
        c3 = (A0) % phi
        C  = (A1 * B0 - A0 * B1) % phi
        u = solve_modeq([c0, c1, c2, c3], C, phi, P64)
        if u is None:
            return None
        small[i] = (u[0], u[1])
        small.setdefault(i + 1, (u[2], u[3]))

    # (b) 복원한 작은 미지수로 x 에 대한 합동식들을 만들고 CRT 결합
    cong = []
    for i in small:
        a_i, x_i = small[i]
        R = (-(a_i * P1024 - x_i + Bv[i])) % phi
        lc = lin_congruence(A[i], R, phi)
        if lc:
            cong.append(lc)
    cur = cong[0]
    for c in cong[1:]:
        m = crt(cur[0], cur[1], c[0], c[1])
        if m:
            cur = m
    x0r, mod = cur
    cnt = phi // mod
    if cnt > 3_000_000:                     # 결합 modulus 가 너무 작으면 포기(재접속)
        return None

    # (c) 잔여류를 열거하여 y 검증 + 서명 r-관계식 검증을 모두 통과하는 생존자 수집
    surv = []
    xc = x0r
    while xc < phi:
        if pow(2, xc, n) == y and verify_x(xc, rs, ss, msgs, e, n, phi):
            surv.append(xc)
        xc += mod
    return surv

# ----------------------------------------------------------------------
# 4) 원격 통신 (socket)
# ----------------------------------------------------------------------
class Remote:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=15)
        self.buf = b""
    def recv_until(self, tok):
        tok = tok.encode() if isinstance(tok, str) else tok
        while tok not in self.buf:
            d = self.s.recv(4096)
            if not d:
                raise EOFError(self.buf)
            self.buf += d
        i = self.buf.index(tok) + len(tok)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out
    def recv_line(self):
        return self.recv_until(b"\n")
    def send_line(self, data):
        self.s.sendall((str(data) + "\n").encode())
    def close(self):
        try: self.s.close()
        except Exception: pass

def parse_ints(b):
    return [int(x) for x in re.findall(rb"-?\d+", b)]

def one_connection(host, port, msgs):
    r = Remote(host, port)
    line = r.recv_until("Pubkey:")
    line += r.recv_line()
    e, phi, n, y = parse_ints(line.split(b"Pubkey:")[1])[:4]
    pub = (e, phi, n, y)

    sigs = []
    for m in msgs:
        r.recv_until("> ")
        r.send_line(0)
        r.recv_until("m: ")
        r.send_line(m)
        sl = r.recv_until("Sig:")
        sl += r.recv_line()
        ri, si = parse_ints(sl.split(b"Sig:")[1])[:2]
        sigs.append((ri, si))

    surv = attack(pub, sigs, msgs)
    if not surv or len(surv) != 1:
        r.recv_until("> ")    # 마지막 슬롯을 소비(아무거나 추측)하고 닫기
        r.send_line(2)
        r.recv_until("x: ")
        r.send_line(0)
        r.close()
        return None, (len(surv) if surv else 0)

    x = surv[0]
    r.recv_until("> ")
    r.send_line(2)
    r.recv_until("x: ")
    r.send_line(x)
    rest = r.s.recv(8192).decode(errors="replace")
    r.close()
    return rest, 1

def remote_attack(host, port):
    msgs = [1, 2, 3, 4]
    for attempt in range(1, 60):
        try:
            rest, ns = one_connection(host, port, msgs)
        except Exception as ex:
            print(f"[!] 접속 {attempt}: 예외 {ex!r} -> 재시도")
            continue
        if rest is None:
            print(f"[*] 접속 {attempt}: 생존자 {ns}명(유일하지 않음) -> 재접속")
            continue
        print(f"[+] 접속 {attempt}: 유일 후보 확보, 추측 전송 완료")
        print(rest)
        if "Flag" in rest or "WOW" in rest:
            return
    print("[!] 시도 횟수 초과")

# ----------------------------------------------------------------------
# 5) 로컬 자체검증 (서버 불필요) — sage 에서 신뢰도 측정용
# ----------------------------------------------------------------------
def selftest(N):
    from Crypto.Util.number import getPrime
    def prg_next(k):
        b = NB >> 4; x = k
        for i in range(NB // 3):
            x ^= k >> (3 * i)
        x &= (1 << b) - 1
        return ((k << b) | x) & (P1024 - 1)
    class Sim:
        def __init__(self):
            self.n_bits = NB
            self.p = getPrime(NB // 2); self.q = getPrime(NB // 2)
            self.n = self.p * self.q
            self.phi = (self.p - 1) * (self.q - 1)
            self.x = random.randint(1, self.n - 1)
            self.y = pow(2, self.x, self.n)
            self.nk = random.getrandbits(NB)
        def pub(self):  return (E, self.phi, self.n, self.y)
        def sign(self, msg):
            k = self.nk; self.nk = prg_next(self.nk)
            t = pow(2, k, self.n)
            r = pow((t << NB) | msg, E, self.n)
            s = (k + self.x * r) % self.phi
            return (r, s)
    msgs = [1, 2, 3, 4]
    uniq_ok = uniq_bad = multi = none = 0
    for _ in range(N):
        sim = Sim(); pub = sim.pub(); truex = sim.x
        sigs = [sim.sign(m) for m in msgs]
        surv = attack(pub, sigs, msgs)
        if not surv:
            none += 1
        elif len(surv) == 1:
            if surv[0] == truex: uniq_ok += 1
            else:                uniq_bad += 1
        else:
            multi += 1
    print(f"[selftest] N={N}")
    print(f"  유일&정답   : {uniq_ok}")
    print(f"  유일&오답   : {uniq_bad}   (0 이어야 함)")
    print(f"  복수생존(재접속): {multi}")
    print(f"  실패/None   : {none}")
    print(f"  => 접속당 즉시성공률 ≈ {uniq_ok}/{N} = {uniq_ok/N:.1%}, "
          f"재접속 포함 기대 성공률 ≈ 100%")

# ----------------------------------------------------------------------
if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) >= 1 and args[0] == "--selftest":
        selftest(int(args[1]) if len(args) > 1 else 100)
    elif len(args) >= 2:
        remote_attack(args[0], int(args[1]))
    else:
        print("usage: sage solve.sage HOST PORT")
        print("       sage solve.sage --selftest 100")
