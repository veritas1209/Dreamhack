from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import hashlib

# 1. output.txt 에서 추출한 파라미터
p = 66022827577630234206900201226653694237482516541293416739143810097575456534711
a = 21830727350005374111533815173558774809900032088784214294773580167177874418026
b = 16417519402258086148333990840097679625247247721631973457292602163259840845901

G_x = 4048844416963878172624527608512156105537155453176803115050991364060528058429
G_y = 2568321437157857181840626182132981959095242627063457885890244082808384026343
P_x = 18967137804592015321433852596446099783651635801031927546667662519327897949264
P_y = 51878950646609279465160873411757881583198147506397321335972377510896867061403
Q_x = 45247794627663199855719600118312767438283240652545104631155981138796271885440
Q_y = 41557770757629901825113762897064437585835652311804577964971081316706921316412

iv = bytes.fromhex("6c638f168c37a477dbc14f8a045548c8")
ct = bytes.fromhex("85130457085fc26b522c106a19cf2aa3a74297e48e39a1b5b230f04bb03da0a8")

# 2. 본래의 타원 곡선과 p-adic (Q_p)로 lift 된 타원 곡선 세팅
F = GF(p)
E = EllipticCurve(F, [a, b])
Eqp = EllipticCurve(Qp(p, 2), [ZZ(a), ZZ(b)])

# 3. G와 P 좌표를 Q_p 위로 올바르게 Lifting
# x좌표만 사용하여 들어올린 후, GF(p) 상에서 y좌표가 원본과 일치하는지 확인 (다르면 부호 반전)
G_qp = Eqp.lift_x(ZZ(G_x))
if F(G_qp.xy()[1]) != F(G_y):
    G_qp = -G_qp

P_qp = Eqp.lift_x(ZZ(P_x))
if F(P_qp.xy()[1]) != F(P_y):
    P_qp = -P_qp

# 4. p-adic Elliptic Logarithm을 찾기 위해 점에 p를 곱함 (이제 정상적으로 타원곡선 점 곱셈 수행)
p_times_G = p * G_qp
p_times_P = p * P_qp

x_g, y_g = p_times_G.xy()
x_p, y_p = p_times_P.xy()

# 5. -(x/y) 공식을 통해 로그 값을 추출
phi_G = -(x_g / y_g)
phi_P = -(x_p / y_p)

# 6. 개인 키 n (P = n * G) 복구
n = ZZ(phi_P / phi_G)
print(f"[*] Recovered Private Key (n): {n}")

# 7. 공유 비밀키(Shared Secret) 계산 후 AES 복호화 진행
Q_point = E(Q_x, Q_y)
shared_secret_point = n * Q_point
shared_secret = int(shared_secret_point.xy()[0])

key = hashlib.sha256(long_to_bytes(shared_secret)).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), 16)

print(f"\n[🎉] FLAG: {flag.decode()}")