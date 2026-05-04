import sys
from math import gcd
from Crypto.Util.number import inverse

# 1. 제공된 데이터 파일 읽기
# (source: 10 의 내용을 output.txt 파일로 저장하세요)
try:
    with open("output.txt", "r") as f:
        lines = f.read().strip().split("\n")
except FileNotFoundError:
    print("[-] output.txt 파일이 필요합니다.")
    sys.exit(1)

data = [(int(x), int(y)) for x, y in (line.split() for line in lines if line.strip())]
N_list = [n for c, n in data]

# 2. 모든 N 쌍에 대해 GCD를 구하여 공통 소인수(Prime factors) 추출
print("[*] 공통 소인수(Prime factors)를 추출하는 중...")
primes = set()
for i in range(len(N_list)):
    for j in range(i + 1, len(N_list)):
        g = gcd(N_list[i], N_list[j])
        # 1보다 크고, 정확히 256비트인 수만 소수로 취급
        # (혹시 두 N이 2개의 소수를 공유하여 512비트가 되더라도 다른 쌍에서 256비트 소수로 걸러집니다)
        if g > 1 and g.bit_length() == 256:
            primes.add(g)

primes = list(primes)
print(f"[+] 총 {len(primes)}개의 고유한 소수를 찾았습니다.")

# 3. 1000개의 암호문을 모두 복호화
print("[*] 각 암호문을 소인수분해하여 복호화하는 중...")
e = 0x10001
plaintexts = []

for ct, n in data:
    temp_n = n
    n_factors = []
    
    # 찾아낸 소수 풀을 이용해 N 소인수분해
    for p in primes:
        if temp_n % p == 0:
            n_factors.append(p)
            temp_n //= p
        if temp_n == 1:
            break
            
    # GCD로 찾지 못한 소수가 하나 남아있다면 추가
    if temp_n > 1:
        n_factors.append(temp_n)
        
    # 오일러 파이 함수 값 계산 및 비밀키 d 도출
    phi = 1
    for p in n_factors:
        phi *= (p - 1)
        
    d = inverse(e, phi)
    pt = pow(ct, d, n)
    plaintexts.append(pt)

# 4. 모든 평문을 XOR 하여 플래그 복원
print("[*] 평문들을 모두 XOR하여 플래그 복원 중...")
# 가장 긴 평문의 바이트 길이를 플래그 길이로 기준 삼음
max_len = max((pt.bit_length() + 7) // 8 for pt in plaintexts)

flag_bytes = [0] * max_len
for pt in plaintexts:
    # 모든 평문을 동일한 바이트 길이로 패딩하여 변환
    pt_bytes_array = pt.to_bytes(max_len, 'big')
    for i in range(max_len):
        flag_bytes[i] ^= pt_bytes_array[i]

flag = bytes(flag_bytes).decode('utf-8', errors='ignore')
print(f"\n[🎉] FLAG FOUND: {flag}")