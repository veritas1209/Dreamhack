import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
from sage.all import *

# --- 1. 문제 파라미터 ---
p = 6031542206422852957835409845440660804307708906943761270361234968437821285371200205241540740092970831805323
a = 1283372795059682794024244496467903566820844997717865718291436837498301447990943570500189725270223907483069
b = 383066366624085155869084505830851719967610032279420258736473053676552836982655017980173317320502708543191
ct_hex = "95efbe44186da4df54edea3c5bd987bb51ee32b32c28d3dc5e2f80c4fd1647b3cbe13fa5dc80a35e2ea186ca3201754a9c35c687311958fe9daf87910bdd1e20a966c2bf7fb5ca2bcaadddb7a79da698"

outputs = [
    5578574258293539897192801993958125405599706910902628586776797763611973630886,
    5628801218948461206396799678697657921698511505298915539633316033641006778729
]

# --- 2. 솔버 함수: Multivariate Coppersmith (LLL + Resultant) ---
def solve_coppersmith(f, bounds, m=3, d=4):
    """
    다변수 Coppersmith 공격을 수행하여 작은 해(h0, h1)를 찾습니다.
    """
    f = f.change_ring(ZZ)
    vars = f.parent().gens()
    X, Y = bounds
    
    # [Step 1] Shifted Polynomials 생성
    # g_{k, i, j} = x^i * y^j * f^k * p^{m-k}
    shifts = []
    for k in range(m + 1):
        for i in range(d - k + 1):
            for j in range(d - k + 1):
                # 차수 제한 (행렬 크기 조절을 위한 가지치기)
                if i + j + k * f.degree() > d + 2:
                   continue
                
                shift = (f ** k) * (p ** (m - k)) * (vars[0] ** i) * (vars[1] ** j)
                shifts.append(shift)
    
    # [Step 2] 격자(Lattice) 행렬 구성
    monomials = set()
    for poly in shifts:
        monomials.update(poly.monomials())
    sorted_monomials = sorted(list(monomials), reverse=True)
    
    matrix_rows = []
    for poly in shifts:
        row = []
        for mon in sorted_monomials:
            # 계수에 Bound 가중치 적용 (X^exp0 * Y^exp1)
            coeff = poly.monomial_coefficient(mon)
            exps = mon.exponents()[0]
            weight = (X ** exps[0]) * (Y ** exps[1])
            row.append(coeff * weight)
        matrix_rows.append(row)
        
    B = Matrix(ZZ, matrix_rows)
    
    # [Step 3] LLL 알고리즘 수행
    print(f"[*] LLL reduction on {B.nrows()}x{B.ncols()} matrix...")
    B = B.LLL()
    print("[*] LLL finished.")
    
    # [Step 4] 짧은 벡터에서 다항식 복원
    pols = []
    for i in range(B.nrows()):
        vec = B[i]
        if vec.is_zero(): continue
        
        terms = []
        is_valid = True
        for j, mon in enumerate(sorted_monomials):
            val = vec[j]
            exps = mon.exponents()[0]
            weight = (X ** exps[0]) * (Y ** exps[1])
            
            if val % weight != 0:
                is_valid = False
                break
            terms.append((val // weight) * mon)
            
        if is_valid:
            pols.append(sum(terms))
            
    # [Step 5] 종결식(Resultant)을 이용해 연립방정식 풀이
    print(f"[*] Found {len(pols)} polynomials. Attempting to solve via Resultant...")
    
    if len(pols) < 2:
        print("[-] Not enough polynomials found.")
        return None
        
    P1 = pols[0]
    P2 = pols[1]
    h0, h1 = vars
    
    try:
        # h1 소거 -> h0에 대한 식 유도
        res_h0 = P1.resultant(P2, h1)
        
        if res_h0.is_constant():
            # 첫 번째 쌍이 실패하면 다음 다항식 시도
            if len(pols) > 2:
                P2 = pols[2]
                res_h0 = P1.resultant(P2, h1)
            else:
                return None
                
        # 1변수 다항식 해 찾기
        univar_pol = res_h0.univariate_polynomial()
        roots_h0 = univar_pol.roots()
        
        for r, multi in roots_h0:
            if r.is_integer():
                cand_h0 = int(r)
                
                # h0 대입하여 h1 찾기
                P1_sub = P1.subs({h0: cand_h0})
                if P1_sub.is_constant(): continue
                    
                roots_h1 = P1_sub.univariate_polynomial().roots()
                for r2, _ in roots_h1:
                    if r2.is_integer():
                        cand_h1 = int(r2)
                        # 범위 대략 체크
                        if abs(cand_h0) < X and abs(cand_h1) < Y:
                            return (cand_h0, cand_h1)
                            
    except Exception as e:
        print(f"[-] Resultant method failed: {e}")
        
    return None

# --- 3. 메인 로직 ---

n = 256
m_bits = 96
y0 = outputs[0]
y1 = outputs[1]

# 다항식 구성
PR = PolynomialRing(ZZ, names=['h0', 'h1'])
h0, h1 = PR.gens()

K = 2**n
# 방정식: (h1*2^n + y1)(h0*2^n + y0) - b(h0*2^n + y0) - a = 0 (mod p)
# 계수가 너무 커지는 것을 방지하기 위해 계수만 mod p 처리 후 정수환 다항식 생성
eq_mod = (h1*K + y1)*(h0*K + y0) - b*(h0*K + y0) - a
eq_coeffs = eq_mod.coefficients()
eq_monoms = eq_mod.monomials()
f = sum([(c % p) * m for c, m in zip(eq_coeffs, eq_monoms)])

print("[*] Starting attack to recover hidden state...")
bounds = (2**m_bits, 2**m_bits)

# 해 찾기 실행
sol = solve_coppersmith(f, bounds, m=3, d=4)

if sol:
    h0_found, h1_found = sol
    print(f"[+] Found h0: {h0_found}")
    
    # 1. 상태 복구 (State Recovery)
    # x1은 첫 번째 출력(y0) 직후의 전체 상태
    x1 = h0_found * (2**n) + y0
    print(f"[+] Recovered x1: {x1}")
    
    # 2. 검증 (Verification)
    x_next = (a * pow(x1, -1, p) + b) % p
    if (x_next & ((1<<n)-1)) == y1:
        print("[+] State Verified! Proceeding to decryption...")
        
        # 3. 키 생성 및 복호화 (Key Generation & Decryption)
        # 현재 x1 상태에서 10번 전진하면 Key 생성 직전 상태(x11)가 됨
        # (문제: 10번 루프 후 11번째 next() 호출 결과가 키)
        
        curr = x1
        for i in range(10):
            curr = (a * pow(curr, -1, p) + b) % p
        
        # 루프가 끝난 시점의 curr가 바로 11번째 상태 (Key Seed)
        key_seed = curr & ((1 << n) - 1)
        print(f"[+] Key Seed (x11): {key_seed}")
        
        # AES 복호화
        key = hashlib.sha256(long_to_bytes(key_seed)).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        ct = bytes.fromhex(ct_hex)
        
        try:
            flag = unpad(cipher.decrypt(ct), 16)
            print(f"\n[SUCCESS] FLAG: {flag.decode()}")
        except Exception as e:
            print(f"[-] Decryption Error: {e}")
            
    else:
        print("[-] Verification failed (Wrong h0 recovered).")
else:
    print("[-] Failed to find solution via Coppersmith attack.")