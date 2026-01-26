# solve_matrix.py
import sys

# 1. 데이터 가져오기
try:
    from extracted_data import dest_indices, src_indices, lut_indices, coeffs
except ImportError:
    print("[!] extracted_data.py 파일이 같은 폴더에 있어야 합니다.")
    sys.exit()

# 2. 설정 값
MOD = 251
FLAG_LEN = 38

# Lookup Table (문제 값)
lut_table = [
    0xef, 0x61, 0x4a, 0x6c, 0xd6, 0xc4, 0xc2, 0x65, 0xd2, 0x1c, 0xc4, 0xd2, 0x0b, 0x9b, 0x60, 0x4c, 
    0xea, 0xda, 0xd8, 0xb8, 0x2f, 0xad, 0xba, 0x19, 0x82, 0xed, 0xf4, 0xb4, 0xd8, 0xd9, 0xa2, 0x95, 
    0xea, 0x5b, 0x89, 0xbc, 0x66, 0x01, 0x00, 0x00
] + [0]*250

# Target (B 벡터)
target_bytes = [
    0x8d, 0x13, 0xaf, 0xeb, 0x43, 0xdd, 0x88, 0xf5, 0xf2, 0xa3, 0xdc, 0xcc, 0x0d, 0x3c, 0x4c, 0xeb, 
    0x52, 0xc8, 0x99, 0x7f, 0x84, 0xf4, 0x54, 0x39, 0x4d, 0xc9, 0xe8, 0x18, 0x7a, 0x94, 0xe0, 0x9e, 
    0x50, 0xa2, 0xc5, 0xc1, 0xaa, 0xb1
]

# -----------------------------------------------------------
# [1] 행렬 A 생성 (Matrix Construction)
# A[row][col] : 입력값 col번째 글자가 결과값 row번째 글자에 더해지는 총 가중치
# -----------------------------------------------------------
matrix = [[0] * FLAG_LEN for _ in range(FLAG_LEN)]
loop_count = len(dest_indices)

print(f"[*] Compressing {loop_count} operations into 38x38 Matrix...")

for i in range(loop_count):
    r = dest_indices[i] & 0xFF  # Row (Output Index)
    c = src_indices[i]          # Col (Input Index)
    
    # 범위를 벗어나는 인덱스는 무시 (플래그 길이 내에서만 영향)
    if r < FLAG_LEN and c < FLAG_LEN:
        lut_val = lut_table[lut_indices[i]]
        coef = coeffs[i]
        
        # 가중치 누적 (Linearity property)
        # Weight = Coeff * LUT_Value
        term = (coef * lut_val) % MOD
        matrix[r][c] = (matrix[r][c] + term) % MOD

# -----------------------------------------------------------
# [2] 가우스 소거법 (Gaussian Elimination over GF(251))
# Ax = B 를 풉니다.
# -----------------------------------------------------------

# 모듈러 역원 구하기 (Extended Euclidean Algorithm)
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1: return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += m0
    return x1

def gaussian_elimination(A, B, p):
    n = len(B)
    # Augmented Matrix [A | B] 생성
    M = [A[i] + [B[i]] for i in range(n)]

    # Forward Elimination
    for i in range(n):
        # Pivot 찾기
        pivot = i
        while pivot < n and M[pivot][i] == 0:
            pivot += 1
        if pivot == n:
            continue # 해가 없거나 무수히 많음 (이 문제에선 발생 안 함)
            
        # Swap rows
        M[i], M[pivot] = M[pivot], M[i]
        
        # Pivot을 1로 만들기 (곱셈의 역원 이용)
        inv = mod_inverse(M[i][i], p)
        for j in range(i, n + 1):
            M[i][j] = (M[i][j] * inv) % p
            
        # 다른 행들의 i번째 열을 0으로 만들기
        for k in range(n):
            if k != i:
                factor = M[k][i]
                for j in range(i, n + 1):
                    M[k][j] = (M[k][j] - factor * M[i][j]) % p

    # 결과 추출 (마지막 열이 해답)
    return [M[i][-1] for i in range(n)]

# -----------------------------------------------------------
# [3] 풀이 및 출력
# -----------------------------------------------------------
print("[*] Solving Linear Equations (Gaussian Elimination)...")
try:
    solution = gaussian_elimination(matrix, target_bytes, MOD)
    
    flag = ""
    for val in solution:
        flag += chr(val)
        
    print("\n" + "="*40)
    print(f"FLAG FOUND: {flag}")
    print("="*40)

except Exception as e:
    print(f"[!] Error solving matrix: {e}")