import hashlib
from pwn import *
import z3

# --- McNie Constants ---
M_VAL = 19
BLK = 10
L = BLK * 3      # 30
NK = BLK * 2     # 20
N = BLK * 4      # 40
POLY = 0x80027   # x^19 + x^5 + x^2 + x + 1

def bin2gf(d_bytes, xlen, m=19):
    """LSB-first 비트스트림을 읽어 GF 원소 배열로 반환"""
    x = [0] * xlen
    bit_str = ''.join(f'{b:08b}'[::-1] for b in d_bytes)
    for i in range(xlen):
        bits = bit_str[i*m : (i+1)*m]
        if len(bits) < m:
            bits += '0' * (m - len(bits))
        x[i] = int(bits[::-1], 2)
    return x

def gf2bin(x, m=19):
    """GF 원소 배열을 LSB-first 비트스트림(바이트 배열)으로 반환"""
    bit_str = ''
    for val in x:
        bit_str += f'{val:019b}'[::-1]
    
    d_bytes = bytearray()
    for i in range(0, len(bit_str), 8):
        chunk = bit_str[i:i+8]
        if len(chunk) < 8:
            chunk += '0' * (8 - len(chunk))
        d_bytes.append(int(chunk[::-1], 2))
    return bytes(d_bytes)

def gf_mul(a, b):
    rst = 0
    for _ in range(19):
        if (b & 1): rst ^= a
        if (a & (1 << 18)):
            a = (a << 1) ^ POLY
        else:
            a <<= 1
        b >>= 1
    return rst & 0x7FFFF

def get_mult_matrix(c):
    """GF(2^19)에서 특정 상수 c를 곱하는 연산을 19x19 이진 행렬로 변환"""
    T = [[0]*19 for _ in range(19)]
    for a in range(19):
        val = gf_mul(1 << a, c)
        for b in range(19):
            if (val >> b) & 1:
                T[a][b] = 1
    return T

def solve_stage(stage, pk_hex, ct_hex, pt_hash):
    print(f"\n[+] --- Stage {stage} 공격 시작 ---")
    pk_bytes = bytes.fromhex(pk_hex)
    ct_bytes = bytes.fromhex(ct_hex)

    pk_gf = bin2gf(pk_bytes, BLK * 5)
    ct_gf = bin2gf(ct_bytes, N + NK)
    c1 = ct_gf[:N]
    c2 = ct_gf[N:]
    
    # 1. G', F 행렬 복원
    G0 = [[0]*N for _ in range(L)]
    for i in range(L): G0[i][i] = 1
    for j in range(BLK):
        G0[0][L+j] = pk_gf[j]
        G0[BLK][L+j] = pk_gf[BLK+j]
        G0[2*BLK][L+j] = pk_gf[2*BLK+j]
    for i in range(1, BLK):
        G0[i][L] = G0[i-1][N-1]
        G0[BLK+i][L] = G0[BLK+i-1][N-1]
        G0[2*BLK+i][L] = G0[2*BLK+i-1][N-1]
        for j in range(L+1, N):
            G0[i][j] = G0[i-1][j-1]
            G0[BLK+i][j] = G0[BLK+i-1][j-1]
            G0[2*BLK+i][j] = G0[2*BLK+i-1][j-1]

    F = [[0]*NK for _ in range(L)]
    for i in range(NK): F[i][i] = 1
    for j in range(NK): F[NK][j] = pk_gf[3*BLK + j]
    for i in range(NK+1, L):
        F[i][0] = F[i-1][BLK-1]
        F[i][BLK] = F[i-1][NK-1]
        for j in range(1, BLK):
            F[i][j] = F[i-1][j-1]
            F[i][BLK+j] = F[i-1][BLK+j-1]

    # 2. 선형 방정식 e = V + x*M 에 필요한 상수행렬 V와 M 계산
    V = c1[:]
    for i in range(20):
        for j in range(40):
            V[j] ^= gf_mul(c2[i], G0[i][j])
            
    M = [[0]*40 for _ in range(10)]
    for i in range(10):
        for j in range(40):
            M[i][j] = G0[20+i][j]
            for k in range(20):
                M[i][j] ^= gf_mul(F[20+i][k], G0[k][j])

    print("[*] 상수행렬 연산 완료. Z3 Boolean 최적화 모델 구축 중...")
    
    # x에 곱해지는 상수들의 비트맵 행렬을 미리 추출 (Z3 과부하 방지)
    T_matrices = [[get_mult_matrix(M[k][i]) for i in range(40)] for k in range(10)]

    # 랭크 기저가 특정 4비트에 예쁘게 안착하지 않을 확률 대비 (최대 5번 재시도)
    for attempt in range(5): 
        basis_indices = [(attempt * 4 + i) % 19 for i in range(4)]
        non_basis_indices = [i for i in range(19) if i not in basis_indices]
        
        # 순수 SAT Solver 사용
        solver = z3.Tactic('sat').solver()
        
        X_vars = [z3.Bool(f'x_{i}') for i in range(190)]
        C_vars = [[z3.Bool(f'c_{i}_{j}') for j in range(4)] for i in range(15)]
        
        e_expr = [[None]*19 for _ in range(40)]
        for i in range(40):
            for b in range(19):
                # 초기값 V[i]의 비트 세팅
                expr = bool((V[i] >> b) & 1)
                terms = []
                for k in range(10):
                    for a in range(19):
                        if T_matrices[k][i][a][b]:
                            terms.append(X_vars[k*19 + a])
                
                # Z3 트리 최적화 (순수 XOR 체인 구성)
                z3_expr = z3.BoolVal(expr)
                for term in terms:
                    z3_expr = z3.Xor(z3_expr, term)
                e_expr[i][b] = z3_expr
        
        # MinRank 조건 설정: 비-기저(Non-basis) 15비트는 기저 4비트의 선형 조합
        for i in range(40):
            for j in range(15):
                rhs = z3.BoolVal(False)
                for k in range(4):
                    rhs = z3.Xor(rhs, z3.And(C_vars[j][k], e_expr[i][basis_indices[k]]))
                solver.add(e_expr[i][non_basis_indices[j]] == rhs)
        
        if solver.check() == z3.sat:
            print(f"[*] SAT 도달 성공! (시도 횟수: {attempt + 1})")
            model = solver.model()
            m_res = [0]*10
            for k in range(10):
                val = 0
                for a in range(19):
                    if z3.is_true(model.evaluate(X_vars[k*19 + a])):
                        val |= (1 << a)
                m_res[k] = val
            
            # 3. 평문 전체 복구
            m_full = [0]*30
            for i in range(20):
                val = c2[i]
                for k in range(10):
                    val ^= gf_mul(m_res[k], F[20+k][i])
                m_full[i] = val
            for i in range(10):
                m_full[20+i] = m_res[i]
                
            pt_bytes = gf2bin(m_full, 19)[:71]
            pt_hex = pt_bytes.hex().upper()
            
            if hashlib.sha256(pt_bytes).hexdigest().upper() == pt_hash:
                print(f"[+] 일치하는 평문 해시 발견! pt = {pt_hex[:20]}...")
                return pt_hex
            
    print("[-] 해를 찾지 못했습니다.")
    return None

def main():
    r = remote("127.0.0.1", 5000)
    
    for st in range(1, 21):
        r.recvuntil(f"=== STAGE {st} ===\n".encode())
        
        pk_line = r.recvline().decode().strip()
        hash_line = r.recvline().decode().strip()
        ct_line = r.recvline().decode().strip()
        
        pk_hex = pk_line.split(" = ")[1]
        pt_hash = hash_line.split(" = ")[1]
        ct_hex = ct_line.split(" = ")[1]
        
        pt_hex = solve_stage(st, pk_hex, ct_hex, pt_hash)
        
        if not pt_hex:
            print("[!] Exploit Failed. 종료합니다.")
            break
            
        r.recvuntil(b"pt? (Uppercase hexademical string) > ")
        r.sendline(pt_hex.encode())
        
        result = r.recvline().decode().strip()
        print(f"[*] 서버 응답: {result}")
        if "Failed" in result:
            break

    r.interactive()

if __name__ == "__main__":
    main()