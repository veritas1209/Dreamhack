from Crypto.Util.number import long_to_bytes, isPrime
import math

# 상수 설정
k1_hex = '12815b6189456f7eae8e16eab976bdd2868065e0a0417a1c95fcf75bc1fd7ebf9388b9e3445262b1bd58798a3a2d9d2832cab2f21f7104e3688afb01467ae1'
k2_hex = '3852a5eaea74c2e07c15a78c5ce6d5778a58d5998eee0421ade2bddf8c527d7c9d85e03e77c3ece257a64806cb11ff168e4e7e4a69140063d8c96c483f4604'
k3_l = 'fc6851611af77ed3b241816041950c9464899c370edb7131913ddb06329ecd85'

K1 = int(k1_hex, 16)
K2 = int(k2_hex, 16)
A = math.isqrt(K1 * 4)
B = math.isqrt(K2 * 4)

# x, y, z는 대략 16~32바이트 사이의 값일 확률이 높습니다. (DH{...} 형식)
# x_est를 기준으로 범위를 훨씬 넓게 잡고 (10^12 이상), 
# 'A % (x+1) == 0' 조건만 빠르게 체크합니다.

# 초기 추정치 재계산 (k3_l의 중간값을 사용하여 더 정확하게)
k3_mid = int(k3_l + '8' * 64, 16)
C_mid = math.isqrt(k3_mid * 4)
x_est = math.isqrt((A * C_mid) // B)

print(f"Target x_est: {x_est}")
print("Starting High-Speed Modulo Scan...")

# 1억(10^8)이 부족했다면 100억(10^10)까지 스캔해봅시다.
# 파이썬에서도 단일 모듈로 연산은 1초에 수백만 번 가능합니다.
limit = 10000000000 # 100억
step = 1000000

for i in range(0, limit, 1):
    # 양방향 탐색
    for delta in [i, -i]:
        if i == 0 and delta == -i: continue
        
        x_plus_1 = x_est + delta + 1
        
        # 조건 1: x+1이 A의 약수인가?
        if A % x_plus_1 == 0:
            y_minus_1 = A // x_plus_1
            y = y_minus_1 + 1
            
            # 조건 2: y+1이 B의 약수인가?
            if B % (y + 1) == 0:
                z_minus_1 = B // (y + 1)
                z = z_minus_1 + 1
                
                # 최종 검증: x, y, z를 합쳐서 플래그 형태인지 확인
                try:
                    m1 = long_to_bytes(x_plus_1 - 1)
                    m2 = long_to_bytes(y)
                    m3 = long_to_bytes(z)
                    flag = m1 + m2 + m3
                    
                    if b'DH{' in flag:
                        print("\n" + "!"*50)
                        print(f"FOUND!")
                        print(f"x: {x_plus_1-1}")
                        print(f"Flag: {flag.decode()}")
                        print("!"*50)
                        exit()
                except:
                    continue
                    
    if i % step == 0 and i != 0:
        print(f"Scanning range: ±{i}...", end='\r')