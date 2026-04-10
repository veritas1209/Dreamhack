import socket
import hashlib

# === CONNECTION SETTINGS ===
HOST = '127.0.0.1' # Change to the challenge host
PORT = 24680       # Change to the challenge port

# --- Helper Functions (Version Independent) ---
# 최신 SageMath와의 호환성을 위해 제너레이터를 명시적으로 선언합니다.
F_256 = GF(256, names=('a',))

def safe_fetch_int(v):
    """구버전(fetch_int), 신버전(from_integer), 혹은 수동 변환을 모두 지원합니다."""
    if hasattr(F_256, 'fetch_int'):
        return F_256.fetch_int(v)
    elif hasattr(F_256, 'from_integer'):
        return F_256.from_integer(v)
    else:
        # 함수가 아예 없는 경우 수동으로 다항식 변환
        return sum(((v >> i) & 1) * (F_256.gen()**i) for i in range(8))

def safe_integer_rep(elem):
    """객체를 다시 정수(바이트)로 변환할 때도 호환성을 탑재합니다."""
    if hasattr(elem, 'integer_representation'):
        return elem.integer_representation()
    else:
        return sum(int(c) << i for i, c in enumerate(elem.polynomial().list()))

def make_upper_diagonal(M):
    n = M.ncols()
    M_new = Matrix(F_256, M)
    for i in range(n):
        for j in range(i + 1, n):
            M_new[i,j] += M_new[j,i]
            M_new[j,i] = 0
    return M_new

def bytes_to_vector(b: bytes):
    return vector(F_256, [safe_fetch_int(v) for v in b])

def vector_to_bytes(vec):
    return bytes(safe_integer_rep(v) for v in vec)

def hash_message(msg: bytes):
    H = hashlib.sha256(msg).digest()
    return bytes_to_vector(H)

def parse_pubkey(pk_bytes, n, m):
    P_list = []
    offset = 0
    for k in range(m):
        mat = []
        for i in range(n):
            row = []
            for j in range(n):
                row.append(safe_fetch_int(pk_bytes[offset]))
                offset += 1
            mat.append(row)
        P_list.append(Matrix(F_256, mat))
    return P_list

# --- Attack Implementation ---
def get_oil_subspace(P_list, m):
    n = 2 * m
    R.<t> = PolynomialRing(F_256)
    S_list = [P + P.transpose() for P in P_list]
    O_basis = []
    
    attempt = 1
    I = identity_matrix(F_256, n)
    
    while len(O_basis) < m:
        print(f"\r    [>] 시도 {attempt}회: 찾은 기저(Basis) 개수 {len(O_basis)}/{m} ... 탐색 중", end="", flush=True)
        
        c_A = [F_256.random_element() for _ in range(m)]
        c_B = [F_256.random_element() for _ in range(m)]
        S_A = sum(c * S for c, S in zip(c_A, S_list))
        S_B = sum(c * S for c, S in zip(c_B, S_list))
        
        if not S_A.is_invertible():
            attempt += 1
            continue
        
        W = S_A.inverse() * S_B
        f = W.charpoly()
        
        h = R(0)
        for i in range(0, f.degree() + 1, 2):
            h += R(f[i].sqrt()) * (t ** (i // 2))
        
        for root, _ in h.roots():
            ker = (W - root * I).right_kernel()
            
            # Kipnis-Shamir에서 이 커널은 보통 2차원(평면)입니다.
            if ker.dimension() >= 2:
                b0 = ker.basis()[0]
                b1 = ker.basis()[1]
                
                # 핵심 최적화: 2차원 평면 내의 모든 선형 결합(256개)을 싹 다 검사!
                candidates = [b0] + [x * b0 + b1 for x in F_256]
                
                for v in candidates:
                    # 진짜 Oil 벡터인지 검증
                    is_oil = True
                    for P in P_list:
                        if v * P * v != 0:
                            is_oil = False
                            break
                    
                    if is_oil:
                        mat = Matrix(O_basis + [v])
                        if mat.rank() > len(O_basis):
                            O_basis.append(v)
                            if len(O_basis) == m:
                                print(f"\r    [+] 수학적 헛스윙 해결! 기저 {m}개 확보! (총 {attempt}회 시도)                ")
                                return O_basis
                            # 이 고유공간에서 기저를 하나 찾았으니 다음 root로 넘어감
                            break
        attempt += 1

    return O_basis

def forge_signature(P_list, msg: bytes, n, m):
    print("[*] Recovering Oil subspace (Kipnis-Shamir)...")
    O_basis = get_oil_subspace(P_list, m)
    
    print("[*] Constructing equivalent private key...")
    U_vin = []
    while len(U_vin) < n - m:
        v = random_vector(F_256, n)
        mat = Matrix(U_vin + [v] + O_basis)
        if mat.rank() == len(U_vin) + 1 + m:
            U_vin.append(v)
    
    U = Matrix(U_vin + O_basis).transpose()
    
    F_eq = []
    for P in P_list:
        F_prime = U.transpose() * P * U
        F_prime = make_upper_diagonal(F_prime)
        F_eq.append(F_prime)
    
    T_eq_inv = U
    
    print("[*] Forging signature...")
    H = hash_message(msg)
    while True:
        v_vin = [F_256.random_element() for _ in range(n - m)]
        v = vector(F_256, v_vin + [0] * m)
        
        mat = Matrix(F_256, [v * F_k for F_k in F_eq])
        target = H - mat * v
        try:
            res = mat[:, n - m:].solve_right(target)
        except ValueError:
            continue
        
        v_full = vector(list(v_vin) + list(res))
        break
    
    sig = T_eq_inv * v_full
    return vector_to_bytes(sig)

# --- Network Interaction ---
def read_until(s, prompt):
    res = b""
    while prompt not in res:
        data = s.recv(1)
        if not data:
            break
        res += data
    return res

if __name__ == "__main__":
    print(f"[*] Connecting to {HOST}:{PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    # 1. Grab Public Key
    print("[*] Receiving public key...")
    pubkey_hex = read_until(s, b"\n").strip().decode()
    pk_bytes = bytes.fromhex(pubkey_hex)
    
    P_list = parse_pubkey(pk_bytes, 64, 32)
    
    # 2. Forge Signature
    msg = b"I love olive oil"
    msg_hex = msg.hex()
    sig_bytes = forge_signature(P_list, msg, 64, 32)
    sig_hex = sig_bytes.hex()
    
    # 3. Send payload and get flag
    read_until(s, b"msg: ")
    print(f"[+] Sending msg: {msg_hex}")
    s.sendall(f"{msg_hex}\n".encode())
    
    read_until(s, b"sig: ")
    print(f"[+] Sending sig: {sig_hex}")
    s.sendall(f"{sig_hex}\n".encode())
    
    print("[*] Awaiting flag...")
    response = s.recv(4096).decode()
    print(f"\n[!] Server Response:\n{response}")