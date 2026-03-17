import math
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

# --- 1. 입력 데이터 세팅 ---
pub_key_pem = """-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKBgQFSOuj6SExa7VtHUvbbnY57
aGVM9brzp5p/Iq4O4CcLaa4Ssj6lc2AY6iAHIgciWDwrYVrnmKyEXaFVZvjvsh9N
snuDq5RpIe3X9GAnvH6BWROxpPwmyPtULcyCFfkx5kR2sjQSVTbRXoste6xNzm63
524mnnhJ2FhXPMLzg/vSmQKBgQEKnblIfuXfwtCild+olEsxXmNu5c/RGi4AOWmm
jMqvGoXYNKW5UvJJwIhjnAkU5JiMWTAjndXZGCZ7xWgZsJ/iziDVVsa3WzFEh494
3TQva3LG9hwOXRYD2BYsSajZ7RWz/yLqKRAmBE5Si2dTxUhmwHgScSKDsSzqKBhc
YFQd2Q==
-----END PUBLIC KEY-----"""

c_hex = "0x2393118ecdee71b12de76cb3bc14dd5dd10e5807e06593d3e2e96b1e53d48592d15da092377299bc66290c661ad0c29c8d12354da0c188c799ae21a29f8062487e0543a2a714d68a37f0f98e102ea0bd5df186c2c2f8fbf277329b8e017e6898d19ad707ccd3b75c1af4bda00ac9cb9710cb7e37bedd7b71d92c000c00b867e8"
c = int(c_hex, 16)

# 공개키 파싱을 통해 N과 e 추출
key = RSA.import_key(pub_key_pem)
N = key.n
e = key.e

# --- 2. Wiener's Attack에 필요한 수학 함수 구현 ---
def rational_to_contfrac(x, y):
    """유리수를 연분수로 변환"""
    a = x // y
    pquotients = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        pquotients.append(a)
    return pquotients

def convergents_from_contfrac(frac):
    """연분수에서 근사분수(Convergents) 생성"""
    convs = []
    for i in range(len(frac)):
        convs.append(contfrac_to_rational(frac[0:i+1]))
    return convs

def contfrac_to_rational(frac):
    """연분수를 다시 유리수로 변환"""
    if len(frac) == 0: return (0, 1)
    num, denom = frac[-1], 1
    for i in range(-2, -len(frac)-1, -1):
        num, denom = frac[i] * num + denom, num
    return (num, denom)

def wiener_attack(e, n):
    """Wiener's Attack 알고리즘 수행"""
    frac = rational_to_contfrac(e, n)
    convergents = convergents_from_contfrac(frac)

    for (k, d) in convergents:
        if k == 0: continue
        # ed = 1 (mod phi) -> (ed - 1)은 k의 배수여야 함
        if (e * d - 1) % k != 0: continue
        
        phi = (e * d - 1) // k
        
        # 근의 공식: x^2 - ((N - phi) + 1)x + N = 0
        b = n - phi + 1
        discriminant = b*b - 4*n
        
        if discriminant >= 0:
            t = math.isqrt(discriminant)
            # 판별식이 완전제곱수이고 해가 정수이면 d를 찾은 것
            if t*t == discriminant and (b + t) % 2 == 0:
                return d
    return None

# --- 3. 익스플로잇 실행 ---
print("[*] Wiener's Attack 진행 중...")
d = wiener_attack(e, N)

if d:
    print(f"[+] 취약한 개인키(d) 획득 성공!\nd = {d}\n")
    # 복호화: m = c^d mod N
    m = pow(c, d, N)
    flag = long_to_bytes(m).decode('utf-8', errors='ignore')
    print(f"[+] FLAG: {flag}")
else:
    print("[-] 공격 실패. 다른 방법이 필요할 수 있습니다.")