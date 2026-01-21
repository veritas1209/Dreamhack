from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad
import base64
from sage.modules.free_module_integer import IntegerLattice

# [1] 문제 값 설정
MULT = 0x570a9ec8b8a9e8005d20abb2e555e29d
M = 0x100000000000000000000000000000000
h = [
    29186099369194997890922604909306052608, 
    96546435635255329419749944464313942016, 
    150895939852556399276298410260405682176
]
iv_b64 = '/5E2ciAHa0oGBEkIzoRV1A=='
ct_b64 = '+huZfkhjnNtH4sxZrItOxbJmu3RvMyOfNQH69axnX/nQcEw2iwTrZRgZyzbL8FoGB7uE5nEm2WLl8ZK5HFBCuq0ZaVv/u17pAJ23dHBqtA7Dp1hdj/gHjR6Ja+Ok7d4G5oPnMfN6xd79uuKjzwgt4w=='

# [2] 3D Lattice 구성
# 식 1: l0 * MULT - l1 = h1 - h0 * MULT (mod M)
# 식 2: l0 * MULT^2 - l2 = h2 - h0 * MULT^2 (mod M)
# 목표: (l1, l2, l0) 벡터가 작게 나오는 l0 찾기

K1 = (h[1] - h[0] * MULT) % M
K2 = (h[2] - h[0] * pow(MULT, 2, M)) % M

# Basis Matrix (3x3)
# [ M       , 0         , 0 ]
# [ 0       , M         , 0 ]
# [ MULT    , MULT^2    , 1 ]
L_matrix = Matrix(ZZ, [
    [M, 0, 0],
    [0, M, 0],
    [MULT, pow(MULT, 2, M), 1]
])

lat = IntegerLattice(L_matrix)

# Target Vector: (K1, K2, 0)
target = vector(ZZ, [K1, K2, 0])

print("[*] Solving CVP with 3D Lattice...")
closest = lat.closest_vector(target)

# closest = (..., ..., l0)
l0 = closest[2]

print(f"[*] Recovered l0: {l0}")

# [3] 초기 시드 복구
S0 = h[0] + l0

# 검증
S1 = (S0 * MULT) % M
calc_h1 = S1 - (S1 % 2**64)

if calc_h1 == h[1]:
    print("[+] Seed recovery VERIFIED!")
else:
    print("[-] Verification failed. But trying decryption anyway...")

# [4] Key 생성
# Loop 2 times
curr = S0
for _ in range(2):
    curr = (curr * MULT) % M

# Next -> Key
curr = (curr * MULT) % M
key_int = curr
key = long_to_bytes(key_int, 16)
print(f"[*] Key: {key.hex()}")

# [5] 복호화
try:
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ct_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    
    # Padding 제거
    flag = unpad(plaintext, AES.block_size).decode()
    print(f"\n[+] FLAG: {flag}")
except Exception as e:
    print(f"\n[-] Decryption Error: {e}")
    # 패딩 에러가 나면 원문 강제 출력
    if 'plaintext' in locals():
        print(f"[*] Raw Plaintext: {plaintext}")
