from pwn import *
import math
import sys

# 엄청나게 큰 수(약 26만 비트)의 연산이 포함되므로 Python의 문자열 변환 제한을 해제합니다.
sys.set_int_max_str_digits(1000000)

# TODO: 실제 문제 서버 주소와 포트로 변경하세요.
host = 'host8.dreamhack.games'
port = 20424

def get_enc(p_conn, val):
    p_conn.sendlineafter(b"> ", b"1")
    p_conn.sendlineafter(b"pt > ", str(val).encode())
    p_conn.recvuntil(b"enc(val) = ")
    return int(p_conn.recvline().strip())

def get_dec(p_conn, val):
    p_conn.sendlineafter(b"> ", b"2")
    p_conn.sendlineafter(b"ct > ", str(val).encode())
    p_conn.recvuntil(b"dec(val) = ")
    return int(p_conn.recvline().strip())

def crt(a, m, b, n):
    inv = pow(m, -1, n)
    return (a + m * ((b - a) * inv % n)) % (m * n)

def solve():
    # 1. Wrap-around가 발생하지 않는 세션을 찾을 때까지 재연결하며 n1, n4 추출
    while True:
        try:
            p_conn = remote(host, port, level='error')
            print("\n[*] Trying new connection to extract n1 and n4...")

            # n4 추출 시도
            y1 = get_dec(p_conn, -1)
            z1 = get_enc(p_conn, y1)
            n4_cand1 = z1 + 1

            y2 = get_dec(p_conn, -2)
            z2 = get_enc(p_conn, y2)
            n4_cand2 = z2 + 2

            if n4_cand1 != n4_cand2:
                print("[-] Wrap occurred for n4. Reconnecting...")
                p_conn.close()
                continue

            n4 = n4_cand1

            # n1 추출 시도
            y3 = get_enc(p_conn, -1)
            z3 = get_dec(p_conn, y3)
            n1_cand1 = z3 + 1

            y4 = get_enc(p_conn, -2)
            z4 = get_dec(p_conn, y4)
            n1_cand2 = z4 + 2

            if n1_cand1 != n1_cand2:
                print("[-] Wrap occurred for n1. Reconnecting...")
                p_conn.close()
                continue

            n1 = n1_cand1
            print(f"[+] Perfect Session Found!")
            print(f"  -> n1 = {n1}")
            print(f"  -> n4 = {n4}")
            break
        except Exception as e:
            p_conn.close()
            continue

    # 2. p, q, s 계산
    p_prime = math.gcd(n1, n4)
    q = n1 // p_prime
    s = n4 // p_prime
    print("\n[+] Primes Extracted (p, q, s):")
    print(f"  -> p = {p_prime}")
    print(f"  -> q = {q}")
    print(f"  -> s = {s}")

    e = 521
    ds = pow(e, -1, s - 1)

    # 3. r 추출을 위한 M 리스트 생성 함수 (CRT 활용)
    def get_M_list(x):
        print(f"[*] Computing Multipliers for x = {x}...")
        v4 = get_enc(p_conn, x)
        v1 = pow(x, e, n1)

        A = pow(v1, e, q)
        B = pow(v4, ds * ds % (s - 1), s)

        V = crt(A, q, B, s)
        qs = q * s

        M_list = []
        for k in range(10):
            v2_cand = V + k * qs
            v1_e = v1 ** e # v1^521: 매우 큰 수치 계산
            if v1_e >= v2_cand:
                M = (v1_e - v2_cand) // q
                M_list.append(M)
        return M_list

    # 교차 검증을 위해 서로 다른 x값으로 거대한 배수 M값들을 생성
    M1_list = get_M_list(2)
    M2_list = get_M_list(3)
    M3_list = get_M_list(4)

    r = None
    print("[*] Calculating GCDs to isolate 'r' (This involves 266k-bit integers, give it a second)...")
    for m1 in M1_list:
        for m2 in M2_list:
            for m3 in M3_list:
                g = math.gcd(m1, math.gcd(m2, m3))
                if g > 1:
                    # 쓰레기 소인수들 제거
                    for p_small in range(2, 1000):
                        while g % p_small == 0:
                            g //= p_small
                    
                    # 남은 수가 256비트 부근의 소수라면 r입니다.
                    if 255 <= g.bit_length() <= 256:
                        r = g
                        break
            if r: break
        if r: break

    if not r:
        print("[-] Could not isolate r! Please try running again.")
        p_conn.close()
        exit()

    print(f"\n[+] Final Prime Extracted:")
    print(f"  -> r = {r}")

    # 4. 모든 모듈러 및 비밀키 생성 후 secret 복호화
    n2 = q * r
    n3 = r * s

    d1 = pow(e, -1, (p_prime - 1) * (q - 1))
    d2 = pow(e, -1, (q - 1) * (r - 1))
    d3 = pow(e, -1, (r - 1) * (s - 1))
    d4 = pow(e, -1, (s - 1) * (p_prime - 1))

    print("\n[*] Entering Challenge Mode (Option 3)...")
    p_conn.sendlineafter(b"> ", b"3")
    p_conn.recvuntil(b"enc(secret) = ")
    C = int(p_conn.recvline().strip())
    print(f"[*] Server generated Encrypted Secret: {C}")

    print("[*] Decrypting offline using recovered private keys...")
    v = pow(C, d4, n4)
    v = pow(v, d3, n3)
    v = pow(v, d2, n2)
    secret = pow(v, d1, n1)

    print(f"[+] Recovered Secret: {secret}")
    
    # 플래그 획득
    p_conn.sendlineafter(b"secret > ", str(secret).encode())
    response = p_conn.recvall(timeout=2).decode().strip()
    
    print("\n" + "="*50)
    print("🎯 FLAG OBTAINED!")
    print(response)
    print("="*50)

if __name__ == "__main__":
    solve()