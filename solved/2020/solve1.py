import random

# 1. 암호화된 16진수 문자열
hex_string = "484d8656736966787175727b64677d68646b73677f62595b5c5c5683"
encrypted = bytes.fromhex(hex_string)

# 2. 난수 생성 (문제 조건: Seed 64)
random.seed(64)
seed_rand = [random.randint(0, 5) for _ in range(len(encrypted))]

# 3. Shift 값 생성 (사용자 제공 코드 진행 기반)
# 코드 진행: C G/B Am E F C/E Dm G | C G/B Am E F C Am Dm G C
# Root 매핑: C=1, D=2, E=3, F=4, G=5, A=6, B=7
# (C/E는 Root C, G/B는 Root G 등으로 처리)

# Part A (8개): C(1), G(5), Am(6), E(3), F(4), C(1), Dm(2), G(5)
part_a = [1, 5, 6, 3, 4, 1, 2, 5]

# Part B (10개): C(1), G(5), Am(6), E(3), F(4), C(1), Am(6), Dm(2), G(5), C(1)
part_b = [1, 5, 6, 3, 4, 1, 6, 2, 5, 1]

# 전체 코드 진행 (18개)
chord_progression = part_a + part_b

# 암호문 길이(28)만큼 코드 진행 반복 적용
# 18개 적용 후, 다시 처음부터 10개 적용
shifts = []
for i in range(len(encrypted)):
    shifts.append(chord_progression[i % len(chord_progression)])

# 4. 복호화 수행
# 공식: ord(flag) = Encrypted - shift - rand
flag = ""
for i in range(len(encrypted)):
    val = encrypted[i] - shifts[i] - seed_rand[i]
    flag += chr(val)

print(f"Decrypted Flag: {flag}")