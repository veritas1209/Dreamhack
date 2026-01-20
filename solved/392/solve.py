from Crypto.Util.number import inverse

# secp160r1 곡선의 Order (n)
n = 0x0100000000000000000001f4c8f927aed3ca752257

# 문제에서 주어진 데이터 (첫 번째와 두 번째 행만 있으면 충분합니다)
# r, s, k_partial, hash(z)
data = [
    (0x92acb929727872bc1c7a5f69c1c3c97ae1c333e2, 0xe060459440ebc11a7cd811a66a341f095f5909e5, 0xef2b0000, 0x68e548ef4984f6e7d05cbcea4fc7c83393806bbf),
    (0xb0f5df566a323de9c9449b925d29b84a607c6b5d, 0x84e39e417e47b4fcaf344255103c61ecaaec4129, 0xc1c00000, 0x1a79e7b0308805508d79f2600a01e70d4f56559e)
]

# 첫 번째 데이터셋
r1, s1, k1_prefix, z1 = data[0]
# 검증용 두 번째 데이터셋
r2, s2, k2_prefix, z2 = data[1]

print("[*] Brute-forcing lower 16 bits of k1...")

# k는 32비트이며, 상위 16비트는 k1_prefix와 같습니다.
# 하위 16비트(0 ~ 65535)를 반복합니다.
for i in range(65536):
    # 후보 k 생성
    k_guess = k1_prefix + i
    
    # ECDSA 개인키 복구 공식: d = r^(-1) * (s * k - z) mod n
    try:
        r_inv = inverse(r1, n)
        d_candidate = (r_inv * (s1 * k_guess - z1)) % n
        
        # 구한 d가 맞는지 두 번째 데이터로 검증
        # k2 = s2^(-1) * (z2 + r2 * d) mod n
        s2_inv = inverse(s2, n)
        k2_derived = (s2_inv * (z2 + r2 * d_candidate)) % n
        
        # 검증 조건:
        # 1. 복구된 k2의 상위 16비트가 주어진 k2_prefix와 일치하는가?
        # 2. k2가 32비트 범위 내에 있는가?
        if (k2_derived & 0xFFFF0000) == k2_prefix and k2_derived < (1 << 32):
            print(f"[+] Found Private Key d: {hex(d_candidate)}")
            
            # 플래그 형식 출력 (40글자 hex, lowercase)
            key_hex = f"{d_candidate:040x}"
            print(f"[*] Flag: DH{{{key_hex}}}")
            break
            
    except Exception as e:
        continue