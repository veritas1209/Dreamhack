from Crypto.Util.number import *

# 주어진 값
e = 65537
d = 22800184635336356769510601710348610828272762269559262549105379768650621669527077640437441133467920490241918976205665073

print("="*70)
print("[*] FactorDB 결과 기반 공격 v2 - 중간 소인수 포함")
print("="*70)
print()

ed_minus_1 = e * d - 1

# FactorDB에서 얻은 소인수들
print("[FactorDB 결과]")
print("e*d - 1 = 2^4 · 3 · 5^2 · 37 · 1117 · 4029461")
print("          · 1403014978139 · 284368748316481195117")
print("          · [77자리 미분해 수]")
print()

# 모든 소인수들
factors = {
    2: 4,    # 2^4
    3: 1,    # 3^1
    5: 2,    # 5^2
    37: 1,
    1117: 1,
    4029461: 1,
    1403014978139: 1,
    284368748316481195117: 1
}

def generate_k_candidates_extended(max_k=10000000):
    """중간 소인수를 포함한 k 후보 생성"""
    candidates = []
    
    # 작은 소인수 조합
    small_base = [1, 2, 3, 4, 5, 6, 8, 10, 12, 15, 16, 20, 24, 25, 30, 
                  37, 40, 48, 50, 60, 75, 100, 111, 120, 148, 150, 185, 200]
    
    # 중간 소인수들
    medium = [1117, 4029461]
    
    # 1단계: 작은 소인수만
    candidates.extend(small_base)
    
    # 2단계: 작은 소인수 * 중간 소인수
    for s in small_base[:15]:  # 너무 많아지지 않게
        for m in medium:
            k = s * m
            if k < max_k:
                candidates.append(k)
    
    # 3단계: 중간 소인수끼리
    candidates.append(1117)
    candidates.append(4029461)
    candidates.append(1117 * 1117)
    candidates.append(1117 * 4029461)
    
    return sorted(set(candidates))

k_candidates = generate_k_candidates_extended()
print(f"[*] 생성된 k 후보: {len(k_candidates)}개")
print(f"[*] 주요 k 후보 (처음 30개):")
for i in range(0, min(30, len(k_candidates)), 10):
    print(f"    {k_candidates[i:i+10]}")
print()

def try_k_value(k, ed_minus_1, search_range=10000000):
    """특정 k 값으로 p, q 복구 시도"""
    if ed_minus_1 % k != 0:
        return None, None
    
    phi = ed_minus_1 // k
    
    # q는 256비트 소수
    p_estimate = phi >> 256
    
    if p_estimate < 2:
        return None, None
    
    # p 근처 탐색
    p_min = max(2, p_estimate - search_range)
    p_max = p_estimate + search_range
    
    for p in range(p_min, p_max):
        if phi % (p - 1) != 0:
            continue
        
        q = (phi // (p - 1)) + 1
        
        # q가 256비트인지 확인
        if q.bit_length() != 256:
            continue
        
        # 소수 확인
        if not isPrime(p):
            continue
        
        if not isPrime(q):
            continue
        
        # 최종 검증
        phi_check = (p - 1) * (q - 1)
        if (e * d - 1) % phi_check == 0:
            return p, q
    
    return None, None

print("[*] k 후보 시도 중...")
print()

found = False
for i, k in enumerate(k_candidates, 1):
    if i % 10 == 1 or k > 1000:
        phi_size = (ed_minus_1 // k).bit_length() if ed_minus_1 % k == 0 else 0
        p_est_size = phi_size - 256 if phi_size > 256 else 0
        print(f"[{i:3d}/{len(k_candidates)}] k = {k:15,} (φ: {phi_size}bit, p 예상: {p_est_size}bit)")
    
    p, q = try_k_value(k, ed_minus_1)
    
    if p is not None:
        print("\n" + "="*70)
        print("[+] 성공!")
        print("="*70)
        print(f"k = {k:,}")
        print()
        print(f"p = {p}")
        print(f"q = {q}")
        print()
        print(f"p 비트: {p.bit_length()}")
        print(f"q 비트: {q.bit_length()}")
        print(f"n = p*q 비트: {(p*q).bit_length()}")
        print()
        
        # Flag 복구
        flag_bytes = long_to_bytes(p)
        try:
            if all(32 <= b < 127 for b in flag_bytes):
                flag_str = flag_bytes.decode('ascii')
                print(f"[+] Flag: {flag_str}")
            else:
                print(f"[+] Flag (bytes): {flag_bytes}")
                print(f"[+] Flag (hex): {hex(p)}")
        except Exception as ex:
            print(f"[+] Flag (hex): {hex(p)}")
            print(f"[!] 디코딩 오류: {ex}")
        
        print("="*70)
        found = True
        break

if not found:
    print("\n" + "="*70)
    print("[-] 모든 k 후보에서 실패")
    print("="*70)
    print()
    print("[분석]")
    print("1. p 탐색 범위가 부족할 수 있습니다 (현재: ±10M)")
    print("2. k가 더 큰 소인수 조합일 수 있습니다")
    print("3. 큰 소인수를 포함할 수 있습니다:")
    print(f"   - 1403014978139")
    print(f"   - 284368748316481195117")
    print()
    print("[제안 1] 탐색 범위 늘리기")
    print("  try_k_value(k, ed_minus_1, search_range=50000000)")
    print()
    print("[제안 2] 큰 소인수 시도")
    print("  k = 3 * 1403014978139")
    print("  k = 12 * 1403014978139")
    print()
    
    # 큰 소인수 몇 개만 빠르게 시도
    print("[*] 큰 소인수 포함 k 몇 개 시도 중...")
    large_k_candidates = [
        3 * 1403014978139,
        12 * 1403014978139,
        6 * 1403014978139,
        1403014978139,
        3 * 284368748316481195117,
    ]
    
    for k in large_k_candidates:
        if ed_minus_1 % k != 0:
            continue
        
        phi = ed_minus_1 // k
        p_est = phi >> 256
        print(f"  k = {k:,} → p 예상: {p_est.bit_length()}bit")
        
        # 좁은 범위로 빠르게 시도
        p, q = try_k_value(k, ed_minus_1, search_range=1000000)
        if p is not None:
            print(f"\n[+] 발견! k = {k}")
            print(f"p = {p}")
            flag_bytes = long_to_bytes(p)
            try:
                print(f"Flag: {flag_bytes.decode('ascii')}")
            except:
                print(f"Flag: {hex(p)}")
            break