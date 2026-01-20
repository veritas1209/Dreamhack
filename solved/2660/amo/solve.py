import struct

# 1. 게임 내 상수 정의
MOD = 4294967296  # 2^32 (var_0_8)
A = 1664525       # Multiplier (var_0_9)
C = 1013904223    # Increment (var_0_10)
INITIAL_KEY = 3237998146 # (var_0_26.key 초기값)
TARGET_COUNT = 999999999999 # (var_0_22)

# 암호화된 데이터 (var_0_17)
ENCRYPTED_BYTES = [
    184, 69, 54, 45, 52, 184, 115, 85, 48, 100, 163, 125, 5, 121, 204, 89, 
    140, 159, 43, 143, 56, 205, 142, 25, 219, 89, 179, 87, 74, 72, 149, 44, 
    148, 180, 11, 178, 124, 173, 183, 83, 62, 96
]

# 2. 행렬 곱셈 함수 (LCG 점프용)
def mat_mul(m1, m2, mod):
    result = [[0, 0], [0, 0]]
    for i in range(2):
        for j in range(2):
            for k in range(2):
                result[i][j] = (result[i][j] + m1[i][k] * m2[k][j]) % mod
    return result

# 3. 행렬 거듭제곱 함수 (빠른 거듭제곱)
def mat_pow(mat, power, mod):
    result = [[1, 0], [0, 1]] # 단위 행렬
    while power > 0:
        if power % 2 == 1:
            result = mat_mul(result, mat, mod)
        mat = mat_mul(mat, mat, mod)
        power //= 2
    return result

# 4. 키 계산 (LCG 1조번 스킵)
print(f"[*] Calculating key after {TARGET_COUNT} steps...")
matrix = [[A, C], [0, 1]]
final_matrix = mat_pow(matrix, TARGET_COUNT, MOD)

# 행렬 적용: [Key_new, 1] = Matrix * [Key_old, 1]
# Key_new = (Mat[0][0] * Key_old + Mat[0][1] * 1) % MOD
final_key = (final_matrix[0][0] * INITIAL_KEY + final_matrix[0][1]) % MOD
print(f"[*] Final Key: {final_key}")

# 5. 복호화 로직 구현 (Lua 코드 포팅)
# var_0_14: 비트 믹싱 함수
def scramble(val):
    val &= 0xFFFFFFFF
    # bxor(val, lshift(val, 13))
    val ^= (val << 13) & 0xFFFFFFFF
    # bxor(val, rshift(val, 17))
    val ^= (val >> 17)
    # bxor(val, lshift(val, 5))
    val ^= (val << 5) & 0xFFFFFFFF
    return val

# var_0_16: 인덱스별 키 생성
CONST_VAL = 2654435769 # (var_0_15)

def get_byte_key(key, index):
    # (key + index * const) % mod
    val = (key + index * CONST_VAL) % MOD
    val = scramble(val)
    return val & 255 # band(val, 255)

# 복호화 실행
flag = ""
for i, enc_byte in enumerate(ENCRYPTED_BYTES):
    # Lua는 인덱스가 1부터 시작하므로 i + 1을 넘겨줌
    idx = i + 1
    key_byte = get_byte_key(final_key, idx)
    decrypted_char = chr(enc_byte ^ key_byte)
    flag += decrypted_char

print(f"\n[+] Flag: {flag}")