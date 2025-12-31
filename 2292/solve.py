from Crypto.Util.number import long_to_bytes
import math

# Factordb에서 얻은 A의 소인수들
factors = [2, 3, 5, 31159, 6737417, 40846715158597602007177181, 15127308428001897497914240572659503451]

# 주어진 상수
k1_hex = '12815b6189456f7eae8e16eab976bdd2868065e0a0417a1c95fcf75bc1fd7ebf9388b9e3445262b1bd58798a3a2d9d2832cab2f21f7104e3688afb01467ae1'
k2_hex = '3852a5eaea74c2e07c15a78c5ce6d5778a58d5998eee0421ade2bddf8c527d7c9d85e03e77c3ece257a64806cb11ff168e4e7e4a69140063d8c96c483f4604'

A = math.isqrt(int(k1_hex, 16) * 4)
B = math.isqrt(int(k2_hex, 16) * 4)

# x+1은 A의 약수들의 조합입니다.
# 38자리 소수 자체가 x+1이거나, 여기에 작은 인수(2, 3, 5 등)가 곱해진 형태일 것입니다.
p38 = 15127308428001897497914240572659503451

print("Checking combinations of factors...")

# 모든 약수 조합을 검사할 필요 없이, x_est와 크기가 비슷한 조합 위주로 확인
from itertools import combinations

def get_all_divisors(factors):
    divs = {1}
    for f in factors:
        new_divs = set()
        for d in divs:
            new_divs.add(d * f)
        divs.update(new_divs)
    return divs

# 작은 인수들만 조합
small_divs = get_all_divisors([2, 3, 5, 31159, 6737417, 40846715158597602007177181])

for d in small_divs:
    # x_plus_1 후보: p38에 작은 인수 d를 곱함
    x_plus_1 = p38 * d
    
    if A % x_plus_1 == 0:
        y_minus_1 = A // x_plus_1
        y = y_minus_1 + 1
        
        # y+1이 B의 약수인지 확인
        if B % (y + 1) == 0:
            z_minus_1 = B // (y + 1)
            z = z_minus_1 + 1
            
            try:
                m1 = long_to_bytes(x_plus_1 - 1)
                m2 = long_to_bytes(y)
                m3 = long_to_bytes(z)
                flag = m1 + m2 + m3
                
                if b'DH{' in flag:
                    print("\n" + "="*50)
                    print("SUCCESS!")
                    print(f"Flag: {flag.decode()}")
                    print("="*50)
                    exit()
            except:
                continue

print("Done. If not found, try multiplying p38 with other combinations.")