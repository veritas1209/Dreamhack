import math

# 주어진 상수 K1
k1_hex = '12815b6189456f7eae8e16eab976bdd2868065e0a0417a1c95fcf75bc1fd7ebf9388b9e3445262b1bd58798a3a2d9d2832cab2f21f7104e3688afb01467ae1'
K1 = int(k1_hex, 16)

# (x+1)(y-1) = 2*sqrt(K1)
# 4*K1의 제곱근을 구하면 정수 A가 나옵니다.
A = math.isqrt(K1 * 4)

print("--- Copy the value below ---")
print(A)
print("----------------------------")

# 참고: A가 실제로 완전제곱수인지 확인 (True가 나와야 함)
print(f"Is 4*K1 a perfect square? {math.isqrt(K1 * 4)**2 == K1 * 4}")