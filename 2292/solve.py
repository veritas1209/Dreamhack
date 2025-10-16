from Crypto.Util.number import *
import itertools

# 주어진 값들
k1 = '12815b6189456f7eae8e16eab976bdd2868065e0a0417a1c95fcf75bc1fd7ebf9388b9e3445262b1bd58798a3a2d9d2832cab2f21f7104e3688afb01467ae1'
k2 = '3852a5eaea74c2e07c15a78c5ce6d5778a58d5998eee0421ade2bddf8c527d7c9d85e03e77c3ece257a64806cb11ff168e4e7e4a69140063d8c96c483f4604'
k3_l = 'fc6851611af77ed3b241816041950c9464899c370edb7131913ddb06329ecd85'

# r 값 추측 (16진수)
r = 16

# 방정식 분석:
# f(a,b,k): (a² + 1)(b² + 1) - 2(a - b)(ab - 1) = 4(k + ab)
# 전개하면:
# a²b² + a² + b² + 1 - 2a²b + 2ab - 2ab² + 2b = 4k + 4ab
# a²b² + a² + b² + 1 - 2a²b - 2ab² + 2ab + 2b = 4k + 4ab
# a²b² - 2a²b - 2ab² + a² + b² - 2ab + 2b + 1 = 4k
# 
# 좌변을 인수분해:
# a²b² - 2a²b - 2ab² + a² + b² - 2ab + 2b + 1
# = (ab)² - 2ab(a+b) + a² + b² - 2ab + 2b + 1
# = (ab - a - b + 1)²
# 
# 따라서: (ab - a - b + 1)² = 4k
# 즉: ab - a - b + 1 = ±2√k

def solve_for_pair(k_hex, r=16):
    """주어진 k에 대해 (a, b) 쌍을 찾음"""
    k = int(k_hex, r)
    
    # ab - a - b + 1 = ±2√k
    # (a-1)(b-1) = ±2√k
    
    sqrt_k = int(k ** 0.5)
    if sqrt_k * sqrt_k != k:
        print(f"k is not a perfect square: {k}")
        # 근사값 사용
        sqrt_k_approx = k ** 0.5
        print(f"sqrt(k) ≈ {sqrt_k_approx}")
    
    solutions = []
    
    for sign in [1, -1]:
        target = sign * 2 * int(k ** 0.5)
        
        # (a-1)(b-1) = target
        # a와 b를 찾기 위해 target의 약수를 찾음
        
        if target <= 0:
            continue
            
        # target의 약수 찾기
        divisors = []
        for i in range(1, min(int(target**0.5) + 1000, target + 1)):
            if target % i == 0:
                divisors.append(i)
                if i != target // i:
                    divisors.append(target // i)
        
        for d in divisors:
            a = d + 1
            b = (target // d) + 1
            
            # 검증
            if (a*a+1)*(b*b+1) - 2*(a-b)*(a*b-1) == 4*(k + a*b):
                solutions.append((a, b))
                
    return solutions

print("=== Solving the equations ===\n")

print("Solving for (x, y) from k1...")
solutions_xy = solve_for_pair(k1, r)
print(f"Found {len(solutions_xy)} solutions")

for i, (x, y) in enumerate(solutions_xy[:10]):
    print(f"\nSolution {i+1}: x={x}, y={y}")
    try:
        m1 = long_to_bytes(x)
        m2 = long_to_bytes(y)
        print(f"  As bytes: m1={m1}, m2={m2}")
        print(f"  Printable: {m1.decode('ascii', errors='ignore')} | {m2.decode('ascii', errors='ignore')}")
    except Exception as e:
        print(f"  Cannot convert to bytes: {e}")

# k1과 k2로부터 y를 교차 확인
print("\n\nSolving for (y, z) from k2...")
solutions_yz = solve_for_pair(k2, r)
print(f"Found {len(solutions_yz)} solutions")

for i, (y, z) in enumerate(solutions_yz[:10]):
    print(f"\nSolution {i+1}: y={y}, z={z}")
    try:
        m2 = long_to_bytes(y)
        m3 = long_to_bytes(z)
        print(f"  As bytes: m2={m2}, m3={m3}")
        print(f"  Printable: {m2.decode('ascii', errors='ignore')} | {m3.decode('ascii', errors='ignore')}")
    except Exception as e:
        print(f"  Cannot convert to bytes: {e}")

# 교차점 찾기 (y 값이 일치하는 경우)
print("\n\n=== Finding consistent solutions ===")
for x, y1 in solutions_xy[:20]:
    for y2, z in solutions_yz[:20]:
        if y1 == y2:
            print(f"\nFound consistent solution!")
            print(f"x={x}, y={y1}, z={z}")
            try:
                m1 = long_to_bytes(x)
                m2 = long_to_bytes(y1)
                m3 = long_to_bytes(z)
                flag_candidate = m1 + m2 + m3
                print(f"Flag candidate: {flag_candidate}")
                print(f"Printable: {flag_candidate.decode('ascii', errors='ignore')}")
            except Exception as e:
                print(f"Error: {e}")