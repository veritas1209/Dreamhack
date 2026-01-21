from Crypto.Util.number import long_to_bytes, isPrime
from math import gcd

# 문제에서 주어진 좌표값
P1 = (21684180133424657511908369853584326789584407745866503260005237244804501663485673507743999830168738515920475505397147129936455872516435874218934858867286, 9763706949425045696239856203319721634651686079372917598096103959266021015809340290573645001094754815339744526369875908753458477171793951934899015829432213)
P2 = (3865282561441917111097438332833281019701235953095756474399511232727733568725305310302820930535014143646393229192851828528117617926536647780118370128895467, 2915748263224875166581455340510964093183982791887736849301749464166783597624989961203946732747921120506820178248459777623588802298333173585030523625245325)
P3 = (9253221412839934605959466611792221672234892566989578166122978239122939479980612545578690850417393772880978906487067870158689416892921352803249492146065862, 10362305272922186509640051458762453666233283531768323022875900413033956429399167629165847484989496982355965974110192365015911019136199717750618765316280099)

def solve():
    # 1. 선형 시스템을 위한 행과 행렬식 함수 준비
    def get_row(P):
        x, y = P
        # 방정식: a*(x^2) + b*(y^2) + d*(-x^2*y^2) = 1 (mod p)
        return [x**2, y**2, -(x**2 * y**2)]

    row1 = get_row(P1)
    row2 = get_row(P2)
    row3 = get_row(P3)
    
    def det3x3(m):
        return (m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) -
                m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0]) +
                m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]))

    # Determinant D 계산
    M = [row1, row2, row3]
    D = det3x3(M)
    
    # Db 계산 (b를 위한 Cramer's rule)
    M_b = [
        [row1[0], 1, row1[2]],
        [row2[0], 1, row2[2]],
        [row3[0], 1, row3[2]]
    ]
    Db = det3x3(M_b)
    
    # Dd 계산 (d를 위한 Cramer's rule)
    M_d = [
        [row1[0], row1[1], 1],
        [row2[0], row2[1], 1],
        [row3[0], row3[1], 1]
    ]
    Dd = det3x3(M_d)
    
    # 2. p 복구
    # 관계식: x_new^2 * (D + Dd * x^2 * y^2)^2 - 4 * D * Db * x^2 * y^2 = K * p
    def calc_poly(P_curr, P_next):
        xc, yc = P_curr
        xn, yn = P_next
        term1 = xn**2 * (D + Dd * xc**2 * yc**2)**2
        term2 = 4 * D * Db * xc**2 * yc**2
        return term1 - term2

    val1 = calc_poly(P1, P2)
    val2 = calc_poly(P2, P3)
    
    p_candidate = gcd(val1, val2)
    p_candidate = abs(p_candidate)

    # [수정된 부분] p_candidate는 p의 배수일 수 있습니다.
    # D와 공약수가 있다면 제거하여 실제 p를 찾습니다.
    # D와 p_candidate가 서로소가 될 때까지 공약수를 나눕니다.
    while True:
        common = gcd(p_candidate, D)
        if common == 1:
            break
        p_candidate //= common

    # 혹시 남은 작은 인수(2, 3 등)가 있을 수 있으므로 큰 소수가 남을 때까지 나눕니다.
    # 문제에서 p는 512비트 소수라고 했습니다.
    for small_p in [2, 3, 5]:
        while p_candidate % small_p == 0:
            p_candidate //= small_p

    p = p_candidate
    
    # p가 정상적으로 소수인지 확인 (디버깅용)
    if not isPrime(p):
        print(f"Warning: Recovered p is not prime. Bit length: {p.bit_length()}")
    
    # 3. d 계산 및 플래그 복구
    try:
        # d = Dd / D mod p
        d_val = (Dd * pow(D, -1, p)) % p
        flag = long_to_bytes(d_val)
        print(f"Recovered p: {p}")
        print(f"Flag: {flag.decode()}")
    except Exception as e:
        print("Error recovering flag:", e)

if __name__ == "__main__":
    solve()