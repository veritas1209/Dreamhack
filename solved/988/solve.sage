from Crypto.Util.number import long_to_bytes

def solve_crt(residues, moduli):
    R = 0
    M = 1
    for r, m in zip(residues, moduli):
        g, u, v = xgcd(M, m)
        if (r - R) % g != 0:
            continue
        R = R + ((r - R) // g) * u * M
        M = (M * m) // g
        R %= M
    return R, M

def parse_matrix(lines, rows, cols):
    M = []
    for line in lines:
        line = line.strip()
        if not line or 'X' in line: continue
        row = []
        for c in line:
            val = ord(c) - 0x10900
            for j in range(4):
                row.append((val >> j) & 1)
        M.append(row[:cols])
    return matrix(GF(2), M)

def parse_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        raw_data = f.read()
    
    separator = " " * 56 + "X" * 16
    blocks = raw_data.split(separator)
    
    lines_P = blocks[1].strip().split('\n')
    lines_v = blocks[2].strip().split('\n')
    lines_w = blocks[3].strip().split('\n')
    
    P = parse_matrix(lines_P, 512, 512)
    v = parse_matrix(lines_v, 1, 512)
    w = parse_matrix(lines_w, 1, 512)
    return P, v, w

def apply_poly(vec, poly, mat):
    res = matrix(GF(2), 1, mat.ncols())
    curr = vec
    for c in poly.list():
        if c == 1:
            res += curr
        curr = curr * mat
    return res

equations = []

for idx in range(5):
    print(f"\nProcessing out{idx}.bin...")
    try:
        P, v, w = parse_file(f"out{idx}.bin")
    except Exception as e:
        print(f"Failed to parse out{idx}.bin: {e}")
        continue
    
    minpoly = P.minimal_polynomial()
    factors = minpoly.factor()
    
    for f, mult in factors:
        d = f.degree()
        # 탐색 차수를 250까지 대폭 늘립니다.
        if d <= 1 or d > 250:  
            continue
            
        g = minpoly // f
        v_prime = apply_poly(v, g, P)
        w_prime = apply_poly(w, g, P)
        
        if v_prime.is_zero():
            continue
            
        M_basis = []
        curr = v_prime
        for _ in range(d):
            M_basis.append(curr[0])
            curr = curr * P
            
        M_basis_mat = matrix(GF(2), M_basis)
        try:
            h = M_basis_mat.solve_left(w_prime[0])
        except ValueError:
            continue
            
        K = GF(2**d, name='a', modulus=f)
        a = K.gen()
        
        Hx = sum(int(h[i]) * (a**i) for i in range(d))
        if Hx == 0:
            continue
            
        mod = a.multiplicative_order()
        
        # Pohlig-Hellman 알고리즘이 멈추지 않도록 소인수가 너무 큰 경우(40비트 이상) 스킵
        largest_prime = mod.factor()[-1][0]
        if largest_prime > 2**40:
            print(f" > Skipping degree {d} (Largest prime is too big: {largest_prime.nbits()} bits)")
            continue
            
        try:
            rem = discrete_log(Hx, a)
            equations.append((rem, mod))
            print(f" > Found relation: e ≡ {rem} mod {mod} (Degree: {d})")
        except Exception as e:
            print(f" > Discrete log failed for degree {d}: {e}")

if equations:
    rem, mod = solve_crt([eq[0] for eq in equations], [eq[1] for eq in equations])
    print("\n[+] Calculation Complete!")
    print(f"Total Modulus M is {mod.nbits()} bits long.")
    
    if mod.nbits() < 512:
        print("[-] Warning: The total modulus might still be too small for the full FLAG.")
        
    print(f"e = {rem}")
    try:
        flag_bytes = long_to_bytes(int(rem))
        print(f"FLAG = DH{{{flag_bytes.decode()}}}")
    except:
        print(f"FLAG (raw bytes) = {flag_bytes}")
else:
    print("[-] No equations found.")