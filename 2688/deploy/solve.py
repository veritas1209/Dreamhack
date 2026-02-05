from Crypto.Util.number import inverse

# 32비트 마스킹 함수
def d32(v):
    return v & 0xFFFFFFFF

# 목표값 (Trace에서 추출한 검증 값)
targets = [
    0x4D864C11, # Index 0
    0x4D691F2E, # Index 1
    0x8CFE0CB0, # Index 2
    0xBDDE93BD, # Index 3
    0x501E0894, # Index 4
    0x97B173FD, # Index 5
    0x99999999, # Index 6
    0x57585757  # Index 7
]

# 키 값 (Trace에서 추출한 연산자)
keys = [
    0x0B0A0908,
    19,
    0x11111111,
    23,
    0x44444444,
    0x55555555,
    0x66666666,
    0x57585757
]

inputs = []

# Index 0: ADD 역연산 (SUB)
inputs.append(d32(targets[0] - keys[0]))

# Index 1: MUL 역연산 (Modular Inverse)
inv_19 = inverse(19, 2**32)
inputs.append(d32(targets[1] * inv_19))

# Index 2: ADD 역연산 (SUB)
inputs.append(d32(targets[2] - keys[2]))

# Index 3: MUL 역연산 (Modular Inverse)
inv_23 = inverse(23, 2**32)
inputs.append(d32(targets[3] * inv_23))

# Index 4: XOR 역연산 (XOR)
inputs.append(d32(targets[4] ^ keys[4]))

# Index 5: XOR 역연산 (XOR)
inputs.append(d32(targets[5] ^ keys[5]))

# Index 6: XOR 역연산 (XOR)
inputs.append(d32(targets[6] ^ keys[6]))

# Index 7: XOR 가정 (Target == Key 이므로 Input은 0)
inputs.append(0) 

print("Calculated Inputs (Hex):")
for i, v in enumerate(inputs):
    print(f"Index {i}: {hex(v)}")

print("\nPayload (Little Endian Bytes):")
payload = b""
for v in inputs:
    payload += v.to_bytes(4, byteorder='little')
print(payload)

# 결과를 보기 좋게 출력
print("\nHuman Readable (Result):")
try:
    print(payload.decode('utf-8', errors='ignore'))
except:
    pass