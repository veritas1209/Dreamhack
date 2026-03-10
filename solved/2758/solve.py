# 1. 메모리에서 추출한 타겟 배열 (Little-Endian)
target_bytes = [
    0xc3, 0x1c, 0xbb, 0x63, 0x7b, 0x24, 0xac, 0xf5, # local_38
    0xd4, 0xb4, 0x65, 0xd6, 0x8d, 0xa5, 0xad, 0xa6, # local_30
    0xef, 0xbe, 0xae, 0x6f, 0x6f, 0x01, 0x7f, 0xf7, # local_28
    0xb8                                            # local_20
]

# 2. 8-bit ROL (Rotate Left) 함수 구현
def ROL8(val, shift):
    val = val & 0xff
    shift = shift & 0x07 # 8로 나눈 나머지
    return ((val << shift) & 0xff) | (val >> (8 - shift))

# 3. 브루트 포스를 이용한 플래그 복구
flag = ""
for i in range(25):
    for c in range(32, 127):  # 출력 가능한 ASCII 범위
        # C코드 연산 재현: (입력문자 ^ 0x23) + (i * 7) + 0x11
        inner_calc = ((c ^ 0x23) + (i * 7) + 0x11) & 0xff
        
        # ROL 함수 결과와 타겟 바이트 비교
        if ROL8(inner_calc, 3) == target_bytes[i]:
            flag += chr(c)
            break

print(f"🎉 Recovered Flag: {flag}")