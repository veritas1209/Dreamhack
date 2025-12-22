"""
P-256 CTF Challenge - Ultimate Solution
가장 짧고 간결하며 이해하기 쉬운 버전
"""

# NIST P-256 곡선 파라미터
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

# 다항식 링 생성 (key1, key2를 변수로)
F.<k1, k2> = PolynomialRing(GF(p))

# 입력 파싱: "숫자 * key1 + 숫자" 형태에서 숫자들 추출
import re
data = [list(map(int, re.findall(r'\d{10,}', line))) 
        for line in open('output.txt').read().strip().split('\n')]

# 각 방정식 쌍에 대해 제약조건 생성
equations = []
for i in range(0, len(data), 2):
    a1, b1 = data[i]      # P.x = a1*k1 + b1
    c1, d1 = data[i+1]    # Q.x = c1*k2 + d1
    
    px = a1*k1 + b1       # P의 x좌표
    qx = c1*k2 + d1       # Q의 x좌표
    
    # 점 배가 공식: 4*(px³ + a*px + b)*(qx + 2*px) = (3*px² + a)²
    eq = 4*(px^3 + a*px + b)*(qx + 2*px) - (3*px^2 + a)^2
    equations.append(eq)

# Ideal의 variety로 해 구하기
solution = ideal(equations).variety()[0]
key1_val = int(solution[k1])
key2_val = int(solution[k2])

# 플래그 생성
flag_value = key1_val ^^ key2_val
print(f"DH{{{flag_value:064x}}}")