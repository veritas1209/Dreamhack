from pwn import *

def solve():
    # 서버 타임아웃이 10초이므로 지연 없이 진행합니다.
    r = remote('host3.dreamhack.games', 8279)

    # 1. 공개키 N값 파싱
    r.recvuntil(b"pub = Pubkey(N=")
    N = int(r.recvuntil(b",", drop=True))
    e = 65537
    log.info(f"N: {N}")

    # 2. 빈 메시지 전송하여 s' (Faulty Signature) 확보
    r.sendlineafter(b"> ", b"")
    r.recvuntil(b"faulty_sig = ")
    s_prime = int(r.recvline().strip())
    log.info(f"Faulty Signature: {s_prime}")

    # 3. 서버가 10번의 입력을 요구하므로, 나머지 9번은 빈 값으로 흘려보냅니다.
    for _ in range(9):
        r.sendlineafter(b"> ", b"")
        r.recvline()

    # 4. SageMath의 small_roots를 이용해 숨겨진 m 복원
    V = pow(s_prime, e, N)

    PR = PolynomialRing(Zmod(N), name='x')
    x = PR.gen()
    f = x - V

    # m은 6바이트이므로 X(해의 상한선)를 2^48로 설정합니다.
    log.info("Calculating small roots using Coppersmith's method...")
    roots = f.small_roots(X=2**48, beta=0.5, epsilon=0.03)

    if not roots:
        log.error("Root not found!")
        return

    m = int(roots[0])
    log.success(f"Recovered padded message (m): {m}")

    # 5. q와 p 계산
    q = gcd(V - m, N)
    p = N // q
    log.success(f"Recovered p: {p}")
    log.success(f"Recovered q: {q}")

    # 6. 정답(p) 전송
    r.sendlineafter(b"> ", str(p).encode())

    # 플래그 획득
    r.interactive()

if __name__ == "__main__":
    solve()