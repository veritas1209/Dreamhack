# 1. 바이너리에서 추출한 비교용 데이터 (DAT_140003000)
dat_values = [
    0x49, 0x60, 0x67, 0x74, 0x63, 0x67, 0x42, 0x66, 
    0x80, 0x78, 0x69, 0x69, 0x7b, 0x99, 0x6d, 0x88, 
    0x68, 0x94, 0x9f, 0x8d, 0x4d, 0xa5, 0x9d, 0x45
]

flag = ""

# 2. 역산 알고리즘 적용
# 공식: Input[i] = (DAT[i] - (i * 2)) ^ i
for i in range(len(dat_values)):
    # 역산 수행 (C 언어의 byte 연산 특성을 위해 & 0xFF 사용)
    char_code = ((dat_values[i] - (i * 2)) ^ i) & 0xFF
    
    # NULL 문자(0x00)가 나오면 종료 (문자열의 끝)
    if char_code == 0:
        break
        
    flag += chr(char_code)

# 3. 결과 출력
print(f"Decoded String: {flag}")
print(f"Final Flag: DH{{{flag}}}")