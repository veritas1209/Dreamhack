import sys

# 1. Target Ciphertext (DAT_00102420)
target_data = [
    0x86, 0x84, 0x7a, 0x0c, 0x1e, 0xf2, 0x76, 0x90, 
    0x73, 0x69, 0xdf, 0x0a, 0x74, 0xea, 0x9e, 0x07, 
    0x3c, 0x49, 0x37, 0xce, 0x33, 0xe3, 0xf0, 0x62, 
    0xa0, 0xf0, 0x94, 0x66, 0x2e, 0xc2, 0x80, 0x64, 
    0x51, 0x64, 0x41, 0xcf, 0x6c, 0x49, 0x29, 0x5c, 
    0xa9, 0x2c, 0x19, 0x6d, 0x26, 0x11, 0x14, 0x61, 
    0x64, 0x24, 0x9d, 0xed, 0x5d, 0xdd, 0xfd, 0x9d, 
    0xed, 0xad, 0xdd, 0xe6, 0x96, 0x55, 0xfd, 0x43
]

# 2. Cube Data Loading
try:
    with open("cube.bin", "rb") as f:
        cube = list(f.read())
    
    # 크기 맞추기 (혹시 덤프가 조금 더 크다면 자르기)
    if len(cube) > 1000:
        cube = cube[:1000]
    elif len(cube) < 1000:
        cube += [0] * (1000 - len(cube))
        
    print(f"[*] cube.bin 로드 완료: {len(cube)} bytes")

except FileNotFoundError:
    print("[!] 오류: 'cube.bin' 파일이 없습니다.")
    sys.exit(1)

# 3. Helper Functions
def ror(val, n):
    n = n % 8
    return ((val >> n) | (val << (8 - n))) & 0xFF

def rotate_cube(param_1, param_2, param_3):
    temp_grid = [[0]*10 for _ in range(10)]
    
    # Extract
    for r in range(10): 
        for c in range(10):
            idx = 0
            if param_1 == 0:   idx = param_2 * 100 + r * 10 + c
            elif param_1 == 1: idx = r * 100 + param_2 * 10 + c
            else:              idx = r * 100 + c * 10 + param_2
            temp_grid[r][c] = cube[idx]

    # Rotate
    rotated_grid = [[0]*10 for _ in range(10)]
    for r in range(10): 
        for c in range(10):
            if param_3 == 0: # Clockwise
                rotated_grid[c][9-r] = temp_grid[r][c] 
            else: # Counter-Clockwise
                rotated_grid[9-c][r] = temp_grid[r][c]

    # Update
    for r in range(10):
        for c in range(10):
            val = rotated_grid[r][c]
            if param_1 == 0:   cube[param_2 * 100 + r * 10 + c] = val
            elif param_1 == 1: cube[r * 100 + param_2 * 10 + c] = val
            else:              cube[r * 100 + c * 10 + param_2] = val

# 4. Decryption Loop
flag = ""
print("[-] 복호화 시작...")

for i in range(64):
    # [수정된 부분]
    # DAT_0010426b는 변수가 아니라 cube[555]의 값입니다. (0x426b - 0x4040 = 0x22b)
    # 큐브가 회전하면서 이 위치의 값도 계속 바뀝니다.
    current_val = cube[0x22b] 
    
    uVar5 = (current_val >> 3)
    uVar6 = (uVar5 * 7 + 0x22b) % 1000
    uVar7 = (uVar6 + uVar5 * 0xd + 1) % 1000
    
    key1 = cube[uVar6]             # cVar2
    shift_amt = cube[uVar7] & 7    # bVar3 & 7
    
    idx_xor = (uVar7 + uVar5 * 0x11 + 2) % 1000
    key2 = cube[idx_xor]           # bVar4 (XOR Key)
    
    encrypted_char = target_data[i]
    
    # --- 역연산 ---
    temp = encrypted_char ^ key2
    temp = ror(temp, shift_amt)
    original_char = (temp - key1) & 0xFF
    
    flag += chr(original_char)
    
    # --- 상태 업데이트 ---
    # 암호화된 값(encrypted_char)을 이용해 큐브 회전
    # current_val (즉 cube[555]) 값을 기준으로 회전 파라미터가 결정됨
    rotate_cube((current_val & 7) % 3, encrypted_char % 10, (current_val & 7) >> 2)

print("\n" + "="*40)
print(f"FLAG: {flag}")
print("="*40)