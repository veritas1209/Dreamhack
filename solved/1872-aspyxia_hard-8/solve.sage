# solve.sage

def solve():

    N = 0xf1081a510d0dc22d620c8634cddcccde28d8b9338c6ef9a4584e55593354465f

   

    targets = [

        0xa09de63b04f4601ca9418ba9dcdbd589a114e0cce80d67796ea2e0d074232e42,

        0x2c9a37007879c163c481557d78124c96e9afc3016028df5ccc50b6d070d14b93,

        0xec82d75b2063c72305b883caa691dff06fe0f5b972f05f07db2d15d04d98cca6,

        0x40ce224b1a683ceea19c770511ca8f8c2e4b8fcbf93895af39869c8155dda2a4

    ]

   

    flag = b""

    print("[*] LLL 격자 축소를 통한 A, B 복원 시작...\n")

   

    for i, T in enumerate(targets):

        # 1. 격자 구성

        M = Matrix(ZZ, [[N, 0], [T, 1]])

       

        # 2. LLL 알고리즘 적용

        red = M.LLL()

       

        # 3. 최단 벡터에서 A, B 추출

        # 3. 최단 벡터에서 A, B 추출

        for row in red:

            # 부호가 다를 수 있으므로 4가지 경우의 수 모두 체크

            for sign_a in (1, -1):

                for sign_b in (1, -1):

                    A = row[0] * sign_a

                    B = row[1] * sign_b

                   

                    if 0 < A < 2**64 and 0 < B < 2**64:

                        if (A * inverse_mod(B, N)) % N == T:

                            print(f"[+] Chunk {i} Found!")

                            print(f"    A = {hex(A)} ({int(A).to_bytes(8, 'big')})")

                            print(f"    B = {hex(B)} ({int(B).to_bytes(8, 'big')})")

                            break



    print(f"\n[🔥] Final Flag: {flag.decode('utf-8', errors='ignore')}")



if __name__ == "__main__":

    solve()