from z3 import *
from cipher import Cipher

# ==========================================
# 1. 암호문 로드
# ==========================================
with open("flag.bmp.enc", "rb") as f:
    ct = f.read()

# 불확실한 파일 크기(2~5번 바이트)는 제외! 무조건 100% 확실한 고정 헤더만 사용합니다.
known_pt = {
    0: 0x42, 1: 0x4D,            # 'B', 'M'
    6: 0, 7: 0, 8: 0, 9: 0,      # 예약 영역
    10: 54, 11: 0, 12: 0, 13: 0, # 오프셋
    14: 40, 15: 0, 16: 0, 17: 0, # DIB 헤더 크기
    26: 1, 27: 0,                # 컬러 플레인
    28: 24, 29: 0,               # 24비트
    30: 0, 31: 0, 32: 0, 33: 0   # 압축 없음
}

dummy_cipher = Cipher([0]*256, 0)

def make_sbox(name, box):
    arr = Array(name, BitVecSort(8), BitVecSort(8))
    for i, v in enumerate(box):
        arr = Store(arr, BitVecVal(i, 8), BitVecVal(v, 8))
    return arr

# ==========================================
# 2. Z3 Solver 및 변수 세팅
# ==========================================
print("[*] Z3 Solver 세팅 중...")
solver = Solver()

z3_s1 = make_sbox('s1', dummy_cipher.s1)
z3_s2 = make_sbox('s2', dummy_cipher.s2)
z3_s3 = make_sbox('s3', dummy_cipher.s3)
z3_s4 = make_sbox('s4', dummy_cipher.s4)
z3_r  = make_sbox('r', dummy_cipher.r)
z3_S1 = make_sbox('S1', dummy_cipher.S1)
z3_S2 = make_sbox('S2', dummy_cipher.S2)
z3_S3 = make_sbox('S3', dummy_cipher.S3)
z3_S4 = make_sbox('S4', dummy_cipher.S4)

nonce = BitVec('nonce', 32)
k_arr = Array('k', BitVecSort(8), BitVecSort(8))
K_arr = Array('K', BitVecSort(8), BitVecSort(8))

# K와 k는 역함수 관계
for i in range(256):
    i_bv = BitVecVal(i, 8)
    solver.add(Select(K_arr, Select(k_arr, i_bv)) == i_bv)
    solver.add(Select(k_arr, Select(K_arr, i_bv)) == i_bv)

# 반복되는 에니그마 코어 로직을 Z3 함수로 분리
def enigma_core(x, ctr):
    a = Extract(7, 0, ctr)
    b = Extract(15, 8, ctr)
    c = Extract(23, 16, ctr)
    d = Extract(31, 24, ctr)
    v1 = Select(z3_s1, x + a)
    v2 = Select(z3_s2, v1 + b)
    v3 = Select(z3_s3, v2 + c)
    v4 = Select(z3_s4, v3 + d)
    v5 = Select(z3_r, v4)
    v6 = Select(z3_S4, v5) - d
    v7 = Select(z3_S3, v6) - c
    v8 = Select(z3_S2, v7) - b
    v9 = Select(z3_S1, v8) - a
    return v9

# ==========================================
# 3. 제약 조건 추가 (Known PT + 주기성 검증)
# ==========================================
print("[*] 고정 헤더 평문 조건 추가...")
for i, pt_val in known_pt.items():
    ct_val = ct[i]
    x = Select(k_arr, BitVecVal(pt_val, 8))
    v9 = enigma_core(x, nonce + i)
    solver.add(Select(K_arr, v9) == BitVecVal(ct_val, 8))

print("[*] 3바이트 주기성(단색 배경) 조건 추가...")
# 54번 바이트부터 픽셀 데이터 시작. 앞부분 100바이트 정도만 추출해서 P[i] == P[i+3] 조건을 줍니다.
for i in range(54, 154):
    c1 = ct[i]
    c2 = ct[i+3]
    
    x1 = Select(k_arr, BitVecVal(c1, 8))
    x2 = Select(k_arr, BitVecVal(c2, 8))
    
    # 평문이 같다는 것은 코어 로직의 결과물(v9)이 같아야 함을 의미합니다. (K 함수 통과 전)
    out1 = enigma_core(x1, nonce + i)
    out2 = enigma_core(x2, nonce + i + 3)
    
    solver.add(out1 == out2)

# ==========================================
# 4. 해독 시작
# ==========================================
print("[*] Z3 연산 시작! (주기성 조건 덕분에 훨씬 안정적일 겁니다)")
if solver.check() == sat:
    print("\n[+] 해답을 찾았습니다!")
    model = solver.model()
    
    recovered_nonce = model[nonce].as_long()
    print(f"[*] 찾은 Nonce: {recovered_nonce}")
    
    recovered_key = []
    for i in range(256):
        val = model.eval(Select(k_arr, BitVecVal(i, 8)), model_completion=True).as_long()
        recovered_key.append(val)
        
    cipher = Cipher(recovered_key, recovered_nonce)
    decrypted = cipher.decrypt(ct)
    
    with open("flag_recovered.bmp", "wb") as f:
        f.write(decrypted)
        
    print("[+] 복호화 완료! 'flag_recovered.bmp' 파일을 열어 플래그를 쟁취하세요!")
else:
    print("[-] 또 해를 찾지 못했습니다. 데이터에 다른 변형이 있는지 확인이 필요합니다.")