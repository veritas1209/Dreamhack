from Crypto.Util.number import long_to_bytes

# 유출된 1600 bits (200 bytes) 데이터
leaked_hex = "984fb55a9f8e179a2effc6521e82db0861b7275d811ae96fd615a60b1331f0aeb61f114af7aa4479a7a2bb00e0c3bb5ed6c9da41ad3a6c462e4dc9903db6037c80ad932530e895c902fda6c0e1771141a335e0f31ced79e45548ba2380e6fb668d1d263fb074584a322ec97d0cbe0eb4a5c271175736bc3d6434f5c18afd0219faf367f8be5c8907a93cade1d43abc7796a3d45e06280614b3dc7075fc1fd7d6ae6a5fc0cf031cda2dc6fd4614aeb96824e85e35279e81262cdb03547e7bbff9b4a861f8e1f273f1"

# 디버깅: 입력값 확인
print("[*] --------------------------------------------------")
print(f"[*] Leaked Hex Length: {len(leaked_hex)} characters")
O2 = int(leaked_hex, 16)
print(f"[*] O2 (Leaked Integer): {hex(O2)[:40]}... (Total {O2.bit_length()} bits)")

# 비트 수 계산 (200바이트 = 1600비트)
N = 200 * 8
print(f"[*] Block Size N: {N} bits")
print("[*] --------------------------------------------------")

# 2차원 격자 기저(Basis) 설정
v1 = (2**N, 0)
v2 = (-O2, 1)

print("[*] Initial Basis Vectors:")
print(f"    v1 = (2^{N}, 0)")
print(f"    v2 = (-O2, 1)")
print("[*] --------------------------------------------------")

def gauss_reduction(v1, v2):
    """
    2D Lattice Reduction (Gauss Algorithm)
    """
    print("[*] Starting Gauss Lattice Reduction (2D SVP)...")
    step = 0
    while True:
        step += 1
        # v1이 항상 더 짧은 벡터가 되도록 스왑
        norm_v1_sq = v1[0]**2 + v1[1]**2
        norm_v2_sq = v2[0]**2 + v2[1]**2
        
        if norm_v1_sq > norm_v2_sq:
            v1, v2 = v2, v1
            norm_v1_sq, norm_v2_sq = norm_v2_sq, norm_v1_sq
        
        # 내적 계산
        dot_product = v1[0]*v2[0] + v1[1]*v2[1]
        
        # 투영 스칼라 계산 (가장 가까운 정수)
        q = round(dot_product / norm_v1_sq)
        
        print(f"    [Step {step}] Reduction factor q = {q}")
        
        if q == 0:
            print(f"[*] Reduction finished successfully after {step} steps.")
            break
            
        # 직교화 진행 (v2 갱신)
        v2 = (v2[0] - q*v1[0], v2[1] - q*v1[1])
        
    return v1, v2

# 가우스 축소 알고리즘 실행
u1, u2 = gauss_reduction(v1, v2)

print("[*] --------------------------------------------------")
print("[*] Reduced Basis Vectors found!")
print(f"    u1 = ({hex(u1[0])[:15]}..., {hex(u1[1])[:15]}...)")
print(f"    u2 = ({hex(u2[0])[:15]}..., {hex(u2[1])[:15]}...)")
print("[*] --------------------------------------------------")

# B값(플래그) 추출 시도
print("[*] Extracting Flag from candidate vectors...")
for idx, v in enumerate([u1, u2]):
    # FLAG는 양수이므로 절댓값을 취함
    B_cand = abs(v[1])
    print(f"    [Candidate {idx+1}] B = {B_cand} ({B_cand.bit_length()} bits)")
    
    try:
        flag_cand = long_to_bytes(B_cand)
        print(f"    [Candidate {idx+1}] Converted to bytes: {flag_cand}")
        
        # 플래그 형식 검증
        if b"DH{" in flag_cand:
            print("\n[+] ==================================================")
            print("[+] SUCCESS: FLAG FOUND!")
            print(f"[+] {flag_cand.decode()}")
            print("[+] ==================================================\n")
            break
    except Exception as e:
        print(f"    [Candidate {idx+1}] Decoding error: {e}")