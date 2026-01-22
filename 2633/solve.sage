# solve.sage
from pwn import *

# Sage 환경에서는 기본적으로 Integer 처리가 빠릅니다.
# pwntools가 없다면: sage -pip install pwntools

HOST = 'host8.dreamhack.games'
PORT = 10154

def solve():
    r = remote(HOST, PORT)

    for stage in range(1, 6):
        print(f"[*] === Stage {stage} ===")
        
        # 데이터 수신 및 파싱
        r.recvuntil(b'n = ')
        n = Integer(r.recvline().strip()) # Sage의 Integer 타입 사용
        
        r.recvuntil(b'e = ')
        e = Integer(r.recvline().strip())
        
        r.recvuntil(b'c = ')
        c = Integer(r.recvline().strip())

        print(f"    n bits: {n.nbits()}")

        # -------------------------------------------------
        # Sage의 강력한 소인수분해
        # ecm.factor(n) 혹은 그냥 factor(n) 사용
        # -------------------------------------------------
        print("    [+] Factoring with Sage...")
        
        # factor(n)은 Factorization 객체를 반환합니다.
        # list(F) -> [(prime, exponent), (prime, exponent), ...]
        F = factor(n) 
        
        # 오일러 피 함수 계산: phi = n * product(1 - 1/p)
        # 혹은 직접 (p-1) * p^(k-1) 계산
        phi = 1
        for p, exponent in F:
            phi *= (p - 1) * (p ** (exponent - 1))

        # 비밀키 d 계산
        d = inverse_mod(e, phi)

        # 복호화
        m = power_mod(c, d, n)
        
        # 포맷팅
        from Crypto.Util.number import long_to_bytes
        flag_str = long_to_bytes(int(m)).decode()
        print(f"    [+] Flag: {flag_str}")
        
        r.sendlineafter(b'dec : ', flag_str.encode())
        
        res = r.recvline()
        if b"Correct" not in res:
            print("Fail")
            break

    print(r.recvall().decode())

solve()