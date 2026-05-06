import json
from pwn import *

# ==========================================
# [1] GCM GF(2^128) 수학 연산 구현부
# ==========================================
def gcm_mult(x: bytes, y: bytes) -> bytes:
    """GF(2^128)에서의 다항식 곱셈 (GCM Bit Reflection 적용)"""
    R = 0xe1000000000000000000000000000000
    Z = 0
    V = int.from_bytes(y, 'big')
    X = int.from_bytes(x, 'big')
    for i in range(128):
        if (X >> (127 - i)) & 1:
            Z ^= V
        if V & 1:
            V = (V >> 1) ^ R
        else:
            V >>= 1
    return Z.to_bytes(16, 'big')

def gcm_add(x: bytes, y: bytes) -> bytes:
    """GF(2^128) 덧셈 (XOR)"""
    return bytes(a ^ b for a, b in zip(x, y))

def gcm_pow(x: bytes, n: int) -> bytes:
    """GF(2^128) 거듭제곱 (빠른 거듭제곱 알고리즘)"""
    res = b'\x80' + b'\x00' * 15 # GCM에서의 1 (항등원)
    base = x
    while n > 0:
        if n & 1:
            res = gcm_mult(res, base)
        base = gcm_mult(base, base)
        n >>= 1
    return res

def gcm_inv(x: bytes) -> bytes:
    """GF(2^128) 역원: 페르마의 소정리에 의해 x^(2^128 - 2)"""
    return gcm_pow(x, (1 << 128) - 2)

def gcm_sqrt(x: bytes) -> bytes:
    """GF(2^128) 제곱근: 특징이 2인 체에서 제곱근은 x^(2^127)"""
    return gcm_pow(x, 1 << 127)

def get_blocks(msg: bytes):
    """메시지를 16바이트 블록으로 분할 (마지막 블록은 0으로 우측 패딩)"""
    blocks = []
    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        if len(block) < 16:
            block += b'\x00' * (16 - len(block))
        blocks.append(block)
    return blocks

def poly_P(msg: bytes, H: bytes) -> bytes:
    """
    메시지 P의 GHASH(다항식) 부분 계산
    Poly(P, H) = P_1*H^(m+1) + P_2*H^m + ... + P_m*H^2
    """
    blocks = get_blocks(msg)
    m = len(blocks)
    res = b'\x00' * 16
    for i, block in enumerate(blocks):
        exp = m + 1 - i
        term = gcm_pow(H, exp)
        term = gcm_mult(block, term)
        res = gcm_add(res, term)
    return res


# ==========================================
# [2] 서버 통신 및 익스플로잇 진행
# ==========================================
def solve():
    host, port = 'host8.dreamhack.games', 22108
    r = remote(host, port)
    
    def sign_up(username: str):
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"Username: ", username.encode())
        r.recvuntil(b"token: ")
        token = r.recvline().strip().decode()
        return bytes.fromhex(token)

    def sign_in(username: str, passcode: str, token: bytes):
        r.sendlineafter(b"> ", b"2")
        r.sendlineafter(b"Username: ", username.encode())
        r.sendlineafter(b"Passcode (Enter if none): ", passcode.encode())
        r.sendlineafter(b"Token: ", token.hex().encode())
        res = r.recvuntil(b"================")
        return b"Welcome" in res

    # 1. 92바이트 페이로드 생성을 위한 유니코드 16글자 트릭
    # "가"(\uac00) = 6바이트. => 14(Prefix) + 4 + 12*6 + 2(Suffix) = 92 Bytes
    u1 = "A" * 4 + "가" * 12
    u2 = "A" * 4 + "가" * 11 + "각" # 마지막 글자만 다르게 조작
    
    print("\n[*] ======= [단계 1] 서명 생성 및 토큰 수집 =======")
    print(f"[*] Registering User 1: {u1}")
    t1 = sign_up(u1)
    print(f"[DEBUG] T1 (Hex) : {t1.hex()}")

    print(f"\n[*] Registering User 2: {u2}")
    t2 = sign_up(u2)
    print(f"[DEBUG] T2 (Hex) : {t2.hex()}")

    # 2. 로컬에서 서버와 동일한 형태의 페이로드 바이트 구성
    p1 = json.dumps({"username": u1}).encode("ascii")
    p2 = json.dumps({"username": u2}).encode("ascii")
    print(f"\n[DEBUG] len(p1) = {len(p1)} bytes, len(p2) = {len(p2)} bytes")
    
    blocks1 = get_blocks(p1)
    blocks2 = get_blocks(p2)

    print("\n[*] ======= [단계 2] 블록 검증 및 H 복구 =======")
    for i in range(len(blocks1)):
        if blocks1[i] != blocks2[i]:
            print(f"[DEBUG] Difference found at Block {i+1}:")
            print(f"  -> P1_Block: {blocks1[i].hex()}")
            print(f"  -> P2_Block: {blocks2[i].hex()}")

    # H 계산: delta_T = delta_P6 * H^2  =>  H^2 = delta_T * inv(delta_P6)
    delta_T = gcm_add(t1, t2)
    delta_P_last = gcm_add(blocks1[-1], blocks2[-1])
    print(f"\n[DEBUG] Delta T    : {delta_T.hex()}")
    print(f"[DEBUG] Delta P_6  : {delta_P_last.hex()}")

    inv_dP = gcm_inv(delta_P_last)
    H_sq = gcm_mult(delta_T, inv_dP)
    H = gcm_sqrt(H_sq)
    print(f"\n[SUCCESS] Recovered H : {H.hex()}")

    # 3. Const 복구 (Nonce와 암호화된 Keystream 등이 합쳐진 마스킹 상수)
    # Const_92 = T1 ^ Poly(P1, H)
    print("\n[*] ======= [단계 3] 마스킹 상수(Const_92) 복구 =======")
    poly_p1 = poly_P(p1, H)
    const_92 = gcm_add(t1, poly_p1)
    print(f"[DEBUG] Poly(P1, H) : {poly_p1.hex()}")
    print(f"[SUCCESS] Const_92  : {const_92.hex()}")

    # 4. Admin 토큰 위조 (Forging)
    print("\n[*] ======= [단계 4] Admin 토큰 위조 및 획득 =======")
    admin_user = "admin"
    admin_pass = "This_is_super_safe_passcode_never_try_to_enter_q1w2w3r4"
    p_admin = json.dumps({"username": admin_user, "passcode": admin_pass}).encode("ascii")
    
    print(f"[DEBUG] Target Admin Payload : {p_admin}")
    print(f"[DEBUG] len(p_admin) = {len(p_admin)} bytes (Must be exactly 92)")
    
    # T_admin = Poly(P_admin, H) ^ Const_92
    t_admin = gcm_add(poly_P(p_admin, H), const_92)
    print(f"\n[SUCCESS] Forged Admin Token : {t_admin.hex()}")

    # 5. Admin으로 로그인 후 플래그 획득
    print("\n[*] ======= [단계 5] Admin 계정으로 인증 시도 =======")
    success = sign_in(admin_user, admin_pass, t_admin)

    if success:
        print("[+] Sign in successful! Getting the flag...")
        r.sendlineafter(b"> ", b"4")
        flag_out = r.recvuntil(b"}").decode()
        print(f"\n[FLAG] \n{flag_out}")
    else:
        print("[-] Sign in failed.")

    r.interactive()

if __name__ == "__main__":
    solve()