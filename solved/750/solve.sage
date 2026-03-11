from Crypto.Util.number import long_to_bytes, bytes_to_long

print("[+] Starting Final Decryption Script...")

# 1. 주어진 데이터
powG_last3 = [
    (51738231919609215543762340804621890760910467305448073852786595659636226859692, 43111893373149284907995444262717445754161097868293099050115310655327291638788),
    (57758880846719127231033528945022034638431932967880805276862917059500697294520, 9415571488547684365368236330475679597478989068059009565745381851001130959366),
    (4666050155980791381393359222981478731602356960992609250610858875221741665515, 27757499057467837934853572874249990711581540384052264031923640368232337554765)
]
Pf = (43255184895684588382079047847411192896918562985184645156596341323186544211025, 27060072553048532925294196325179704389997409237210430375180782715516629666650)
Pp = (27669537313547811948636718240270231219754876486756765917107398641877484033612, 6259918121278884623712796416898524214234714155767948198751404241017250466073)

# 2. 파라미터 동적 복구
x1, y1 = powG_last3[0]
x2, y2 = powG_last3[1]
x3, y3 = powG_last3[2]

X1, Y1, Z1 = x1^2, y1^2, -x1^2 * y1^2
X2, Y2, Z2 = x2^2, y2^2, -x2^2 * y2^2
X3, Y3, Z3 = x3^2, y3^2, -x3^2 * y3^2

M = Matrix(ZZ, [[X1, Y1, Z1], [X2, Y2, Z2], [X3, Y3, Z3]])
Delta = M.determinant()
Delta_a = Matrix(ZZ, [[1, Y1, Z1], [1, Y2, Z2], [1, Y3, Z3]]).determinant()
Delta_b = Matrix(ZZ, [[X1, 1, Z1], [X2, 1, Z2], [X3, 1, Z3]]).determinant()
Delta_d = Matrix(ZZ, [[X1, Y1, 1], [X2, Y2, 1], [X3, Y3, 1]]).determinant()

p = 83291407619946867341079081963574130353730876490901682080022407142424923785337
Zp = IntegerModRing(p)
a = Zp(Delta_a) / Zp(Delta)
b = Zp(Delta_b) / Zp(Delta)
d = Zp(Delta_d) / Zp(Delta)

bsqrt = Zp(x2) * (1 + Zp(d) * Zp(x1)^2 * Zp(y1)^2) / (2 * Zp(x1) * Zp(y1))

# 3. Weierstrass 폼 변환
d_prime = d / b
A_M = 2 * (a + d_prime) / (a - d_prime)
B_M = 4 / (a - d_prime)

a_W = (3 - A_M^2) / (3 * B_M^2)
b_W = (2 * A_M^3 - 9 * A_M) / (27 * B_M^3)
E = EllipticCurve(GF(p), [a_W, b_W])

def to_weierstrass(P_edwards):
    x, y = P_edwards
    X_ed = Zp(x)
    Y_ed = bsqrt * Zp(y)
    u = (1 + Y_ed) / (1 - Y_ed)
    v = u / X_ed
    return E((u + A_M / 3) / B_M, v / B_M)

Pf_W = to_weierstrass(Pf)
Pp_W = to_weierstrass(Pp)

# 4. G 복구 및 **진짜 부분군 위수(Exact Subgroup Order)** 계산
print("[+] Calculating EXACT curve order...")
N = E.order()
t = p + 1 - N

G_W = inverse_mod(int(t - 1), N) * Pp_W

# 핵심 패치: N_small 대신 G가 실제로 생성하는 진짜 부분군의 크기를 사용합니다.
ord_G = G_W.order()
P_large = 276329825157676505786350290575842101958451
O_small = ord_G // P_large
print(f"[+] Exact Generator Small Order (O_small): {O_small}")

print("[+] Recovering M0 in exact smooth subgroup...")
M0 = discrete_log(P_large * Pf_W, P_large * G_W, operation='+')

# 5. 궁극의 BSGS 공격
print("[+] Running BSGS for the remaining missing bits...")

# 플래그 길이에 맞춘 가장 타이트한 경계값 설정 (18 bytes payload + '}')
x_min = bytes_to_long(b"DH{" + bytes([32]*18) + b"}")
x_max = bytes_to_long(b"DH{" + bytes([126]*18) + b"}")

# 올바른 탐색 간격(O_small)을 적용하여 K의 범위를 산출합니다.
k_min = int((x_min - M0) // O_small)
k_max = int((x_max - M0) // O_small + 1)
print(f"[+] Search bounds gap: {k_max - k_min}")

G_prime = O_small * G_W
T_prime = Pf_W - M0 * G_W

# 곡선 위에서 k_min ~ k_max 사이의 정확한 이산 로그를 빠르게 찾아냅니다.
k = discrete_log(T_prime, G_prime, bounds=(k_min, k_max), operation='+')

# 최종 플래그 복구
FLAG_int = M0 + k * O_small
print(f"\n[🎉] FLAG: {long_to_bytes(FLAG_int).decode()}")