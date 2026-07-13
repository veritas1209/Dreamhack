import json
import time
from multiprocessing import Pool, cpu_count
import argparse

# ==========================================
# 1. 초기 세팅 (p 값은 Step 1과 동일)
# ==========================================
p = 89319941268580302833179511371818098358631
Fp = GF(p)
PR_t.<t> = PolynomialRing(Fp)

# output.txt 파싱 데이터 (Step 1에서 썼던 parsed_data.py를 import 하셔도 됩니다)
# 임시로 더미 데이터 구조만 잡아두었습니다. 반드시 실제 데이터로 연결하세요!
from parsed_data import data 

# ==========================================
# 2. 대수적 수 연산 코어 함수
# ==========================================
def compute_power_sums(C_val, max_deg):
    """ X^3 + X - C_val = 0 의 멱합(Power sums) 계산 """
    ps = [Fp(3), Fp(0), Fp(-2)] # P_0 = 3, P_1 = 0, P_2 = -2
    for k in range(3, max_deg + 1):
        ps.append(-ps[k-2] + C_val * ps[k-3])
    return ps

def power_sums_to_poly(ps, degree):
    """ 뉴턴 항등식: 멱합 배열을 다항식 계수로 변환 """
    coeffs = [Fp(1)]
    for k in range(1, degree + 1):
        e_k = sum(((-1)**(i-1) * ps[i] * coeffs[k-i]) for i in range(1, k + 1))
        coeffs.append(e_k / Fp(k))
    
    # 부호 번갈아가며 다항식 계수화
    final_coeffs = [(-1)**i * c for i, c in enumerate(coeffs)]
    return PR_t(final_coeffs[::-1])

# ==========================================
# 3. Worker: 특정 z값에 대해 평가(Evaluation) 수행
# ==========================================
# 전역 변수로 워커가 사용할 relation 정보를 담아둡니다.
WORKER_RELATION = None

def init_worker(relation):
    global WORKER_RELATION
    WORKER_RELATION = relation

def evaluate_at_z(z_val_int):
    z_val = Fp(z_val_int)
    rel = WORKER_RELATION
    
    indices = rel['indices']
    c_vals = rel['c_vals']
    c_z = rel['c_z']
    
    # 양수 파트와 음수 파트 분리
    pos_idx = [i for i, c in enumerate(c_vals) if c > 0]
    neg_idx = [i for i, c in enumerate(c_vals) if c < 0]
    
    # 차수는 3^(factor 개수) = 3^4 = 81
    degree = 81
    
    # --- 1. 양수 파트 계산 ---
    ps_pos = [Fp(1)] * (degree + 1)
    ps_pos[0] = Fp(degree) # P_0 은 항상 차수
    
    for i in pos_idx:
        idx = indices[i]
        c = c_vals[i]
        r_val = data[idx][2] # parsed_data 의 r 값
        C = Fp(r_val) * z_val
        
        # P_{c * k} 추출
        ps_base = compute_power_sums(C, c * degree)
        for k in range(1, degree + 1):
            ps_pos[k] *= ps_base[c * k]
            
    # z^{c_z} 곱해주기 (c_z > 0 일 때 양수 파트에)
    if c_z > 0:
        z_pow = z_val**c_z
        for k in range(1, degree + 1):
            ps_pos[k] *= z_pow**k

    poly_pos = power_sums_to_poly(ps_pos, degree)
    
    # --- 2. 음수 파트 계산 ---
    ps_neg = [Fp(1)] * (degree + 1)
    ps_neg[0] = Fp(degree)
    
    for i in neg_idx:
        idx = indices[i]
        c = -c_vals[i] # 절대값
        r_val = data[idx][2]
        C = Fp(r_val) * z_val
        
        ps_base = compute_power_sums(C, c * degree)
        for k in range(1, degree + 1):
            ps_neg[k] *= ps_base[c * k]
            
    # z^{|c_z|} 곱해주기 (c_z < 0 일 때 음수 파트에)
    if c_z < 0:
        z_pow = z_val**(-c_z)
        for k in range(1, degree + 1):
            ps_neg[k] *= z_pow**k

    poly_neg = power_sums_to_poly(ps_neg, degree)
    
    # --- 3. Resultant (종결식) 계산 ---
    # 두 다항식의 t를 소거하여 z에 대한 순수 평가값 도출
    res = poly_pos.resultant(poly_neg)
    
    return int(res)

# ==========================================
# 4. 메인 실행부
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rel_idx", type=int, required=True, help="어느 relation을 풀 것인가? (0~3)")
    args = parser.parse_args()
    
    with open("relations.json", "r") as f:
        relations = json.load(f)
        
    my_relation = relations[args.rel_idx]
    
    print(f"[*] 사용할 Relation 인덱스: {args.rel_idx}")
    print(f"[*] 사용 가능한 코어: {cpu_count()}개 풀가동 준비 완료!")
    
    # 추정 차수 2^25 정도이므로, 그보다 약간 많은 수의 포인트 평가 필요
    # CTF 시간 관계상 적절히 청크 단위로 파일에 저장하며 진행
    num_evals = 34000000 
    chunk_size = 100000
    
    # 워커 풀 생성 (초기화 함수로 relation 전달)
    pool = Pool(processes=cpu_count(), initializer=init_worker, initargs=(my_relation,))
    
    out_filename = f"evals_poly_{args.rel_idx}.txt"
    print(f"[*] 평가를 시작합니다. 결과는 {out_filename}에 실시간 저장됩니다.")
    
    start_time = time.time()
    
    with open(out_filename, "a") as f:
        for offset in range(1, num_evals + 1, chunk_size):
            end = min(offset + chunk_size, num_evals + 1)
            z_inputs = list(range(offset, end))
            
            # 병렬 매핑!
            results = pool.map(evaluate_at_z, z_inputs)
            
            # 파일에 쓰기
            for r in results:
                f.write(f"{r}\n")
                
            elapsed = time.time() - start_time
            print(f"[+] {end-1} / {num_evals} 완료... 경과 시간: {elapsed:.2f}초")
            
    pool.close()
    pool.join()
    print("[*] 다항식 평가 완료!")