#!/usr/bin/env python3

# 과일 상자 정보
apples_A = 22
tangerines_A = 33
apples_B = 128
tangerines_B = 224

encoded = "1225791960486847216559241057127643735061339219611903419796877670743004960622385174"
numbers = [int(encoded[i:i+2]) for i in range(0, len(encoded), 2)]

print("=" * 60)
print("힌트 재분석")
print("=" * 60)
print("1. 'b_ga_real_im' - 다양한 해석:")
print("   - B가 진짜")
print("   - 비밀 암호?")
print("   - B가 리얼 I'm?")
print()
print("2. '갈아엎었다' - 섞었다는 의미?")
print("   - A와 B 상자 값을 뒤섞어서 사용?")
print()
print("3. '오름차순' - 무엇의 오름차순?")
print("   - 과일 개수? [22, 33, 128, 224]")
print("   - 숫자 자체?")
print()
print(f"4. 숫자 개수: {len(numbers)}개")
print()

print("=" * 60)
print("가설 1: 각 숫자에서 '인덱스+1'번째 과일 키 사용")
print("=" * 60)

# 과일 키를 반복 사용 (22, 33, 128, 224, 22, 33, ...)
fruit_keys = [22, 33, 128, 224]

decoded = [numbers[i] ^ fruit_keys[i % 4] for i in range(len(numbers))]
print(f"XOR 결과: {decoded[:10]}...")
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ ASCII: {result}")
else:
    print("ASCII 범위 아님")

decoded = [numbers[i] + fruit_keys[i % 4] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ 더하기: {result}")

decoded = [numbers[i] - fruit_keys[i % 4] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ 빼기: {result}")

print("\n" + "=" * 60)
print("가설 2: 역순 과일 키 [224, 128, 33, 22]")
print("=" * 60)

fruit_keys_rev = [224, 128, 33, 22]

decoded = [numbers[i] ^ fruit_keys_rev[i % 4] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ XOR: {result}")

decoded = [numbers[i] + fruit_keys_rev[i % 4] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ 더하기: {result}")

decoded = [numbers[i] - fruit_keys_rev[i % 4] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ 빼기: {result}")

print("\n" + "=" * 60)
print("가설 3: 'B만 사용' [128, 224] 반복")
print("=" * 60)

b_keys = [128, 224]

decoded = [numbers[i] ^ b_keys[i % 2] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ XOR: {result}")

decoded = [numbers[i] + b_keys[i % 2] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ 더하기: {result}")

decoded = [numbers[i] - b_keys[i % 2] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ 빼기: {result}")

print("\n" + "=" * 60)
print("가설 4: 'A만 사용' [22, 33] 반복")
print("=" * 60)

a_keys = [22, 33]

decoded = [numbers[i] ^ a_keys[i % 2] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ XOR: {result}")

decoded = [numbers[i] + a_keys[i % 2] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ 더하기: {result}")

decoded = [numbers[i] - a_keys[i % 2] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ 빼기: {result}")

print("\n" + "=" * 60)
print("가설 5: 교차 패턴 [22, 224, 33, 128]")
print("=" * 60)

cross_keys = [22, 224, 33, 128]

decoded = [numbers[i] ^ cross_keys[i % 4] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ XOR: {result}")

decoded = [numbers[i] + cross_keys[i % 4] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ 더하기: {result}")

decoded = [numbers[i] - cross_keys[i % 4] for i in range(len(numbers))]
if all(32 <= d <= 126 for d in decoded):
    result = ''.join([chr(d) for d in decoded])
    print(f"✓✓✓ 빼기: {result}")

print("\n" + "=" * 60)
print("가설 6: 모든 가능한 2개 조합")
print("=" * 60)

all_nums = [22, 33, 128, 224]
from itertools import permutations

for perm in permutations(all_nums, 2):
    keys = list(perm)
    decoded = [numbers[i] ^ keys[i % 2] for i in range(len(numbers))]
    if all(32 <= d <= 126 for d in decoded):
        result = ''.join([chr(d) for d in decoded])
        print(f"✓✓✓ XOR {keys}: {result}")

print("\n" + "=" * 60)
print("완료")
print("=" * 60)