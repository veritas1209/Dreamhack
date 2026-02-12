# 이미지 2에서 추출한 Target 값 (비교 대상 값들)
targets = [
    106, 141, 223, 220, 17, 54, 63, 123, 132, 176, 
    213, 223, 12, 35, 60, 117, 143, 158, 209, 242, 
    254, 40, 67, 109, 124, 176, 195, 223, 248, 25, 
    74, 105, 131, 160, 198, 228, 251, 35, 72, 82, 
    128, 164, 180, 185, 11, 21, 54, 92, 115, 131, 
    196, 224, 246, 20, 65, 96, 128, 162, 142, 235
]

# 상수 정의
SALT_MUL = 31
SALT_ADD = 7
SALT_MOD = 251
CHAR_MOD = 256

flag = ""

# i는 1부터 60까지 (데이터 길이만큼)
for i in range(1, 61):
    # 1. Salt 계산: (i * 31 + 7) % 251
    salt = (i * SALT_MUL + SALT_ADD) % SALT_MOD
    
    # 2. Target 값 가져오기 (인덱스는 0부터 시작하므로 i-1)
    if i-1 < len(targets):
        target = targets[i-1]
        
        # 3. 역연산: (Target - Salt) % 256 = Flag의 아스키 코드
        # 파이썬의 % 연산자는 음수 처리를 자동으로 해주므로 그대로 사용 가능
        char_code = (target - salt) % CHAR_MOD
        
        flag += chr(char_code)

print(f"Recovered Flag: {flag}")