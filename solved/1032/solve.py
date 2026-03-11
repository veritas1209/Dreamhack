from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

M = 2**1024
TRUNC = 512
K = 2**TRUNC

# 데이터 파싱 (넉넉하게 4000개 탐색)
with open('values', 'r') as f:
    values_full = [int(x) for x in f.read().splitlines()]
    values = values_full[:4000]

# Hensel's Lifting: 다항식의 근 a를 modulo 2^1024에서 고속으로 찾습니다.
def get_a(coeffs):
    roots = [1] # 문제에서 a는 항상 홀수 (a | 1)
    for k in range(2, 1025):
        new_roots = []
        mod = 1 << k
        step = 1 << (k-1)
        for r in roots:
            # p(r) mod 2^k 평가
            val, curr = 0, 1
            for c in coeffs:
                val = (val + c * curr) % mod
                curr = (curr * r) % mod
            if val == 0: new_roots.append(r)

            # p(r + step) mod 2^k 평가
            val2, curr2 = 0, 1
            r2 = r + step
            for c in coeffs:
                val2 = (val2 + c * curr2) % mod
                curr2 = (curr2 * r2) % mod
            if val2 == 0: new_roots.append(r2)

        roots = new_roots
        if not roots:
            return None
    return roots

def solve():
    n = 4  # 다항식 차수
    m = 7  # 겹쳐볼 윈도우(방정식)의 개수
    window_size = n + m # 총 11개의 '연속된' 출력이 필요함

    print(f"[*] 절반만 노출된 LCG를 공격합니다. (Multi-Window LLL, 필요 연속 출력: {window_size}개)")

    for start in range(len(values) - window_size):
        Y = values[start:start+window_size]

        # [단계 1] Multi-Window 격자 구성
        dim = m + n + 1
        L = Matrix(ZZ, dim, dim)

        for i in range(n + 1):
            for j in range(m):
                L[i, j] = Y[i + j] * K
            L[i, m + i] = K

        for j in range(m):
            L[n + 1 + j, j] = M

        L_red = L.LLL()

        # [단계 2] 진짜 다항식 추출 및 a 찾기
        for row in L_red:
            coeffs = [row[m + i] // K for i in range(n + 1)]
            if all(c == 0 for c in coeffs): continue
            if coeffs[-1] == 0: continue # 최고차항이 살아있는지 확인

            roots = get_a(coeffs)
            if not roots: continue

            # [단계 3] a를 찾았다면 CVP를 이용해 x0(초기 상태) 복구
            for a in roots:
                W = min(len(Y), 6)
                L_cvp = Matrix(ZZ, W + 1, W + 1)
                L_cvp[0, 0] = 1
                for i in range(1, W): L_cvp[0, i] = power_mod(a, i, M)
                for i in range(1, W): L_cvp[i, i] = M
                for i in range(1, W):
                    L_cvp[W, i] = (Y[0] * power_mod(a, i, M) - Y[i]) * K % M
                L_cvp[W, W] = K

                L_cvp_red = L_cvp.LLL()
                for cvp_row in L_cvp_red:
                    if abs(cvp_row[W]) == K:
                        sign = cvp_row[W] // K
                        e0 = (cvp_row[0] * sign) % K
                        x0 = Y[0] * K + e0

                        # [검증]
                        valid = True
                        curr = x0
                        for i in range(W):
                            if (curr >> TRUNC) != Y[i]:
                                valid = False; break
                            curr = (curr * a) % M
                        if valid:
                            print(f"\n[+] 빙고! {start}번째 위치에서 동기화 성공!")
                            print(f"[+] Multiplier (a) = {a}")
                            return a, x0, start

    return None, None, None

a, x0, start_idx = solve()

if a is not None:
    print("[*] 남은 수열을 따라가며 LCG 상태를 끝까지 동기화합니다...")
    target_idx = start_idx + 1
    current_x = x0

    while target_idx < len(values_full):
        current_x = (a * current_x) % M
        if (current_x >> TRUNC) == values_full[target_idx]:
            target_idx += 1

    print("[+] 동기화 완료! Flag를 복호화합니다.")
    next_x = (a * current_x) % M
    next_value = next_x >> TRUNC

    key = sha256(next_value.to_bytes(512 // 8, 'big')).digest()
    with open("enc", "rb") as f:
        data = f.read()

    iv, ciphertext = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    flag = unpad(cipher.decrypt(ciphertext), 16)

    print("\n[🎯] Flag:", flag.decode('utf-8', errors='ignore'))
else:
    print("[-] 탐색 실패. values 데이터 구간을 늘려야 할 수도 있습니다.")