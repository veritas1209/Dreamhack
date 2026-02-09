import struct

# 1. Z3가 찾아낸 Raw Values (Trace B 기준, SAT 결과)
# 우리는 이 값들이 "거의 정답"이라고 확신할 수 있습니다.
raw_values = [
    0x50, # Block 0: 'P'
    0x63, # Block 1: 'c'
    0x16, # Block 2: 0x16
    0x7a, # Block 3: 'z'
    0x72, # Block 4: 'r'
    0xeb, # Block 5: 0xeb
    0xc0, # Block 6: 0xc0
    0x8b  # Block 7: 0x8b
]

print(f"[*] Raw Z3 Values: {raw_values}")
print(f"[*] ASCII Preview: " + "".join([chr(x) if 32 <= x <= 126 else '?' for x in raw_values]))

print("\n[!] Attempting Brute-force Decoding...")

# 후보군 1: 단순 출력 (이미 확인됨)
decoded = bytearray(raw_values)
print(f"1. Raw: {decoded}")

# 후보군 2: Nibble Swap (0x50 -> 0x05, 0x16 -> 0x61 'a')
# 리버싱 문제에서 자주 나오는 패턴입니다.
swapped = bytearray([((x & 0x0F) << 4) | ((x & 0xF0) >> 4) for x in raw_values])
print(f"2. Nibble Swap: {swapped} -> {swapped.decode('latin-1', 'ignore')}")

# 후보군 3: Bit Inversion (~x)
inverted = bytearray([(~x) & 0xFF for x in raw_values])
print(f"3. Inverted: {inverted}")

# 후보군 4: XOR Brute-force (0x00 ~ 0xFF)
# 키가 한 바이트로 고정되어 있을 가능성
print("\n[*] Searching for XOR Key...")
found_flag = False
for key in range(256):
    xored = bytearray([x ^ key for x in raw_values])
    try:
        # 출력 가능한 문자열인지 확인 (DH{...}, flag{...}, convergent...)
        text = xored.decode('utf-8')
        if text.isprintable():
            print(f"Key 0x{key:02x}: {text}")
            found_flag = True
    except:
        pass

if not found_flag:
    print(" -> No simple XOR key found.")

# 후보군 5: ADD/SUB Key 적용
# 로그에 있던 ADD 키의 바이트들을 이용해 봅니다.
# Block 0 ADD Key: 0x12, 0x34... 
# Block 0 Z3 Value: 0x50 ('P')
# 0x50 ^ 0x12 = 'B', 0x50 + 0x12 = 'b', 0x50 - 0x12 = '>'
add_key_bytes = [0x12, 0x34, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66] # 대략적인 패턴

print("\n[*] Checking specific transformations...")
try:
    # ADD Key와 XOR 해보기
    attempt_xor = bytearray([r ^ k for r, k in zip(raw_values, add_key_bytes)])
    print(f"Values ^ ADD_Key_Bytes: {attempt_xor}")
    
    # ADD Key 더해보기
    attempt_add = bytearray([(r + k) & 0xFF for r, k in zip(raw_values, add_key_bytes)])
    print(f"Values + ADD_Key_Bytes: {attempt_add}")

except Exception as e:
    print(e)