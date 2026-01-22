import sys
# Python 3.11+에서는 큰 정수 변환 시 DoS 방지를 위해 길이 제한이 있습니다.
# 이 문제는 N이 매우 크므로 제한을 해제해야 합니다.
sys.set_int_max_str_digits(0)

from pwn import *
from Crypto.Util.number import long_to_bytes, inverse
from sympy.ntheory import factorint

# ==========================================
# 설정
# ==========================================
HOST = 'host8.dreamhack.games'
PORT = 10154

def solve():
    # 서버 연결
    r = remote(HOST, PORT)

    for stage in range(1, 6):
        print(f"\n[*] === Stage {stage} ===")
        
        # 1. n, e, c 파싱
        r.recvuntil(b'n = ')
        n = int(r.recvline().strip())
        
        r.recvuntil(b'e = ')
        e = int(r.recvline().strip())
        
        r.recvuntil(b'c = ')
        c = int(r.recvline().strip())

        print(f"    n bit_length: {n.bit_length()}")

        # 2. 소인수분해 (Factoring)
        # sympy.factorint는 작은 소인수들을 매우 효율적으로 찾아냅니다.
        print("    [+] Factoring n... (This might take a moment)")
        
        factors = factorint(n)
        
        # factors는 {소수: 지수, ...} 형태의 딕셔너리 반환
        print(f"    [+] Found {len(factors)} distinct prime factors.")

        # 3. 오일러 피 함수 phi(n) 계산
        # phi(n) = product( (p-1) * p^(k-1) )
        phi = 1
        for p, exponent in factors.items():
            phi *= (p - 1) * (p ** (exponent - 1))

        # 4. 비밀키 d 계산
        try:
            d = inverse(e, phi)
        except ValueError:
            print("[!] Error: Inverse likely does not exist (gcd(e, phi) != 1).")
            # 만약 e와 phi가 서로소가 아니라면 문제 의도상 발생하지 않아야 함
            sys.exit(1)

        # 5. 복호화
        m = pow(c, d, n)
        
        # 6. 바이트 변환 및 전송
        # 문제에서 flag는 MD5 해시값(hex string)임
        flag_str = long_to_bytes(m).decode()
        print(f"    [+] Decrypted Flag: {flag_str}")
        
        r.sendlineafter(b'dec : ', flag_str.encode())
        
        # 정답 확인
        result = r.recvline()
        if b"Correct" in result:
            print("    [+] Stage Clear!")
        else:
            print(f"    [-] Failed: {result}")
            sys.exit(1)

    # 모든 스테이지 완료 후 최종 플래그 출력
    print("\n" + "="*50)
    final_response = r.recvall().decode()
    print(final_response)
    print("="*50)

if __name__ == "__main__":
    solve()