import numpy as np
from sympy import Matrix, mod_inverse

MOD = 10**9 + 7

# output.txt에서 데이터 파싱
data = """[889877233, 446181743, 681673138, 164379010, 86787371, 920471415] [871942058, 653661085, 890207967, 210933265, 161823872, 220005109]
[120212990, 25553928, 854407059, 452730157, 389500662, 305812518] [864070207, 610860876, 131000774, 290641619, 199865405, 217394906]
[4296977, 50674908, 182762533, 123135889, 33272283, 375994283] [411259818, 645456487, 676801850, 423058249, 715010983, 154175570]
[786627401, 147571778, 992844690, 296288616, 85533314, 73138183] [782398442, 175866740, 887935094, 508589914, 674538334, 554883403]
[123761512, 286637397, 635876292, 243408427, 842575480, 946844414] [472162564, 270524317, 198188261, 898211886, 794174982, 947379494]
[382810149, 17170371, 890564689, 50030531, 174343093, 326101886] [538131352, 804448054, 977572693, 496179971, 909593095, 681323395]
[262161488, 275237687, 316552929, 921626679, 932004800, 884967592] [735891753, 467486949, 299038103, 438906469, 337382831, 73870706]
[751142121, 768672836, 747530776, 187580923, 424757633, 126393714] [141057907, 533179126, 232443910, 563994359, 218816065, 762342843]"""

enc_flag = [216980125, 650945971, 430915648, 148109781, 149126585, 979440844, 45891232, 689408409, 465249179, 239949047, 47329808, 899688054, 502990278, 318821934, 320201789, 910441719, 634962314, 712943592, 97191640, 599141468, 941764754, 908192127, 197922473, 987500387, 778664577, 264230199, 174609500, 707975808, 86029680, 552636394, 978486630, 85523693, 897146951, 984157564, 328580089, 625223243]

# 평문-암호문 쌍 파싱
lines = data.strip().split('\n')
pairs = []
for line in lines:
    parts = line.split('] [')
    p = eval(parts[0] + ']')
    c = eval('[' + parts[1])
    pairs.append((p, c))

print(f"총 {len(pairs)}개의 평문-암호문 쌍\n")

# 선형 시스템 구성
# C = M * P + V
# 각 암호문 요소 c_i = sum(M[i][j] * p[j]) + V[i]
# 7개 미지수: M의 6개 요소 + V의 1개 요소 (각 행마다)

# sympy를 사용한 정확한 모듈로 역행렬 계산
def solve_linear_system_mod(pairs, mod):
    # 첫 6개 쌍으로 M과 V를 구함
    # C = M*P + V를 확장하여 [C] = [M V] * [P; 1]
    
    # 확장된 평문 행렬 (각 행에 1 추가)
    P_ext = []
    C_list = []
    
    for p, c in pairs[:7]:  # 7개 사용 (과결정 시스템)
        P_ext.append(p + [1])
        C_list.append(c)
    
    # 각 암호문 차원에 대해 독립적으로 풀기
    M_rows = []
    V_elements = []
    
    for dim in range(6):
        # 이 차원에 대한 방정식: c[dim] = M[dim] @ p + V[dim]
        # 7개의 방정식으로 7개의 미지수 (M[dim]의 6개 + V[dim] 1개)
        
        A = Matrix([p + [1] for p, c in pairs[:7]])
        b = Matrix([c[dim] for p, c in pairs[:7]])
        
        try:
            # A * x = b (mod MOD)를 풀기
            # 최소제곱법 사용: A^T * A * x = A^T * b
            AT = A.T
            ATA = (AT * A).applyfunc(lambda x: x % mod)
            ATb = (AT * b).applyfunc(lambda x: x % mod)
            
            # 가우스 소거법으로 풀기
            ATA_inv = ATA.inv_mod(mod)
            x = (ATA_inv * ATb).applyfunc(lambda x: x % mod)
            
            M_rows.append([int(x[i]) % mod for i in range(6)])
            V_elements.append(int(x[6]) % mod)
        except:
            print(f"차원 {dim} 풀이 실패, 다른 방법 시도...")
            # 직접 가우스 소거법
            aug = A.row_join(b)
            rref_result = aug.rref_mod(mod)
            solution = rref_result[0][:, -1]
            M_rows.append([int(solution[i]) % mod for i in range(6)])
            V_elements.append(int(solution[6]) % mod)
    
    M = Matrix(M_rows)
    V = Matrix(V_elements)
    
    return M, V

print("행렬 M과 벡터 V 복원 중...")
M, V = solve_linear_system_mod(pairs, MOD)

print("✓ M과 V 복원 완료!\n")

# 검증
print("검증 중...")
for i, (p, c) in enumerate(pairs):
    p_vec = Matrix(p)
    c_calc = ((M * p_vec + V).applyfunc(lambda x: x % MOD))
    c_expected = Matrix(c)
    match = all((c_calc[j] - c_expected[j]) % MOD == 0 for j in range(6))
    if i < 3 or not match:
        print(f"쌍 {i+1}: {'✓ 일치' if match else '✗ 불일치'}")
    if not match and i < 2:
        print(f"  예상: {c}")
        print(f"  계산: {[int(c_calc[j]) % MOD for j in range(6)]}")

# 플래그 복호화
print("\n플래그 복호화 중...")
try:
    M_inv = M.inv_mod(MOD)
    
    flag = ""
    for i in range(0, len(enc_flag), 6):
        block = enc_flag[i:i+6]
        c_vec = Matrix(block)
        p_vec = (M_inv * (c_vec - V)).applyfunc(lambda x: x % MOD)
        
        for val in p_vec:
            val = int(val) % MOD
            if val > 0 and val < 256:
                flag += chr(val)
            elif val == 0:
                pass  # 패딩
            else:
                print(f"경고: 범위 밖 값 {val}")
    
    print(f"\n🚩 FLAG: {flag}")
    print(f"플래그 길이: {len(flag)} 문자")
except Exception as e:
    print(f"복호화 오류: {e}")
    print("M 행렬이 역행렬을 가지지 않을 수 있습니다.")