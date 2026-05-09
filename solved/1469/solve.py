# Wasm 플래그 리버싱 및 복호화 스크립트
# 내부 검증 로직: Y[i] = ((input[i] ^ data1[i]) * 13 + 37) % 256

# 오프셋 1048576에 위치한 68 bytes 데이터
data1 = (
    b"\x1f\xcd\x88\x9d\xbb+VP\xe6{\xf6\x91\x82\x82|%"
    b"\x19\xa0\x92\x9atn\x96\xe3g#\x0b\xb8\x01\xa93}m"
    b"\xeaB\xcd\x1a \xab\xe8\xe4\xa3'\x87\x97\x0e\x06\xd6"
    b"]vL\xa9\xe4\xd0\x99\xc7!p5\x126\x17\xc5\xeb\xf7\xc1"
    b"\x22\x90"
)

# 오프셋 1048644에 위치한 68 bytes 정답 데이터
target_y = (
    b"\xc4\xe6|\xad[\x1c,\xe3k\x0e\xf2\xb0\xd3\xb9\x01\xf5"
    b"q\xff\xa3\xf1r\xb4\x86\x03\xf8\xa6\x87[\xfd\x8eL"
    b"]\x9a4\xe2\xcad6+'\x10@6\x15\x86\xe3\xc9I\xc8"
    b"e:MQ\x22\xe1Ue\xcd\xc1\xec2\xd2\xa0h\xa9\xca\xb3."
)

print("==================================================")
print(f"[DEBUG] data1 배열 길이 검증: {len(data1)} bytes")
print(f"[DEBUG] target_y 배열 길이 검증: {len(target_y)} bytes")
print("==================================================\n")

flag = ""
for i in range(68):
    # 1. 2단계 산술 역연산: X[i] = ((Y[i] - 37) * 197) % 256
    # (13 * 197 = 2561 ≡ 1 mod 256)
    y_val = target_y[i]
    x_val = ((y_val - 37) * 197) % 256
    
    # 2. 1단계 XOR 역연산: input[i] = X[i] ^ data1[i]
    input_char_code = x_val ^ data1[i]
    input_char = chr(input_char_code)
    flag += input_char
    
    # 디버깅 및 분석을 위한 각 단계별 연산 정보 출력
    print(f"[DEBUG] Index {i:02d} | 원본 Y: {y_val:3d} (0x{y_val:02x}) -> 역연산 X: {x_val:3d} (0x{x_val:02x}) -> data1[i]: {data1[i]:3d} (0x{data1[i]:02x}) -> 글자: '{input_char}' (ASCII: {input_char_code})")

print("\n==================================================")
print(f"[DEBUG] 🚀 최종 복호화된 플래그: {flag}")
print("==================================================")