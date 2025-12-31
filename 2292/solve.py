from Crypto.Util.number import long_to_bytes
import math

# 주어진 상수
k1_hex = '12815b6189456f7eae8e16eab976bdd2868065e0a0417a1c95fcf75bc1fd7ebf9388b9e3445262b1bd58798a3a2d9d2832cab2f21f7104e3688afb01467ae1'
k2_hex = '3852a5eaea74c2e07c15a78c5ce6d5778a58d5998eee0421ade2bddf8c527d7c9d85e03e77c3ece257a64806cb11ff168e4e7e4a69140063d8c96c483f4604'
k3_l = 'fc6851611af77ed3b241816041950c9464899c370edb7131913ddb06329ecd85'

# 1. 상수 K1, K2 계산 및 A, B 도출
# r은 16진수 문자열 구성을 볼 때 16임이 확실함
K1 = int(k1_hex, 16)
K2 = int(k2_hex, 16)

# 식: (x+1)(y-1) = 2 * sqrt(K1)
A = 2 * math.isqrt(K1)
# 식: (y+1)(z-1) = 2 * sqrt(K2)
B = 2 * math.isqrt(K2)

# 2. C값 근사 (k3의 뒷부분을 0으로 채움)
# k1, k2 길이가 128이므로 k3도 128일 것임. k3_l이 64자이므로 나머지 64자를 0으로 채움
k3_min_hex = k3_l + '0' * 64
K3_min = int(k3_min_hex, 16)
C_approx = 2 * math.isqrt(K3_min)

# 3. x 근사값 계산
# x^2 ~ (A * C) / B
x_sq_approx = (A * C_approx) // B
x_est = math.isqrt(x_sq_approx)

# 4. x 주변 탐색 및 플래그 복구
print(f"Searching near x ~ {x_est}...")

# 근사값이 매우 정확할 것이므로 작은 범위만 탐색
for x_candidate in range(x_est - 100, x_est + 100):
    # x+1은 A의 약수여야 함 ((x+1)(y-1) = A)
    if A % (x_candidate + 1) != 0:
        continue
    
    # y 계산
    y_candidate = (A // (x_candidate + 1)) + 1
    
    # y+1은 B의 약수여야 함
    if B % (y_candidate + 1) != 0:
        continue
        
    # z 계산
    z_candidate = (B // (y_candidate + 1)) + 1
    
    # 검증: (z+1)(x-1) 의 제곱을 4로 나눈 값이 k3_l로 시작하는지 확인
    term = (z_candidate + 1) * (x_candidate - 1)
    K3_calc = (term * term) // 4
    k3_calc_hex = hex(K3_calc)[2:]
    
    if k3_calc_hex.startswith(k3_l):
        try:
            m1 = long_to_bytes(x_candidate)
            m2 = long_to_bytes(y_candidate)
            m3 = long_to_bytes(z_candidate)
            flag = m1 + m2 + m3
            print("-" * 20)
            print("Flag Found:")
            print(flag.decode())
            print("-" * 20)
            break
        except:
            continue