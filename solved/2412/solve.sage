from sage.all import *

ans = "70.5590132?293631918670?46822609957?988055033686?1569071970764?1114611560013?117553882470?421130?840438?0358646?50224131?209642792?698833537"

# RealField 객체의 이름을 'R_field'로 명확하게 변경하여 덮어쓰기 방지
R_field = RealField(464)
div_val = ZZ(10**116)

def get_ans(unknown_int):
    flag_bytes = b'KoS{' + int(unknown_int).to_bytes(43, 'big') + b'}'
    flag_int = int.from_bytes(flag_bytes, 'big')
    x = R_field( ZZ(flag_int) / div_val )

    for r in range(20, 101):
        x = ( R_field(r - 1/x)^2 - x^2 )^R_field(0.5)
    return f'{x:f}'

# states: [(현재까지 확정한 ? 숫자들, 탐색 L_bound, 탐색 R_bound)]
states = [("", 0, 256**43 - 1)]

print("ASCII Pruning 기반 완전 탐색을 시작합니다...\n")

for i in range(12):
    print(f"[+] {i+1}/12 번째 '?' 복구 중...")
    next_states = []

    for prefix, L_bound, R_bound in states:
        for d in '0123456789':
            current_guess = prefix + d

            ans_min = ans
            ans_max = ans
            for char in current_guess:
                ans_min = ans_min.replace('?', char, 1)
                ans_max = ans_max.replace('?', char, 1)

            ans_min = ans_min.replace('?', '0')
            ans_max = ans_max.replace('?', '9')

            l, r = L_bound, R_bound
            while l < r:
                m = (l + r) // 2
                if get_ans(m) < ans_min:
                    l = m + 1
                else:
                    r = m
            x_low = l

            l, r = L_bound, R_bound
            while l < r:
                m = (l + r + 1) // 2
                if get_ans(m) > ans_max:
                    r = m - 1
                else:
                    l = m
            x_high = l

            if x_low > x_high:
                continue

            bytes_low = b'KoS{' + int(x_low).to_bytes(43, 'big') + b'}'
            bytes_high = b'KoS{' + int(x_high).to_bytes(43, 'big') + b'}'

            stable_prefix = b""
            for b1, b2 in zip(bytes_low, bytes_high):
                if b1 == b2:
                    stable_prefix += bytes([b1])
                else:
                    break

            if all(32 <= b <= 126 for b in stable_prefix):
                print(f"  -> 유효한 분기 발견: {current_guess:<12} | 확정된 문자열: {stable_prefix.decode('ascii')}")
                next_states.append((current_guess, x_low, x_high))

    states = next_states
    if not states:
        print("[!] 모든 분기가 잘려나갔습니다. 에러 발생.")
        break

print("\n[!] 탐색 완료!")
for prefix, L_bound, R_bound in states:
    flag_bytes = b'KoS{' + int(L_bound).to_bytes(43, 'big') + b'}'
    print(f"Flag: {flag_bytes.decode('ascii', errors='replace')}")