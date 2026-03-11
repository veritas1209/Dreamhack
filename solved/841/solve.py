from pwn import *

# 도커 접속
r = remote('host3.dreamhack.games', 14282)

def get_sbox():
    r.recvuntil(b'='*79 + b'\n')
    sbox = []
    for _ in range(16):
        line = r.recvline().decode().strip().split()
        for val in line:
            if val == '____':
                sbox.append(-1)
            else:
                sbox.append(int(val, 16))
    return sbox

def get_val(idx, sbox_table):
    res = 0
    for i in range(8):
        if (idx >> i) & 1:
            res ^= sbox_table[1 << i]
    return res

# 1. SBox 복구
log.info("Step 1: Recovering SBox...")
sbox_data = get_sbox()
blank_indices = [i for i, x in enumerate(sbox_data) if x == -1]
payload = [f"{get_val(idx, sbox_data):02x}" for idx in blank_indices]
r.sendlineafter(b'(hex)> \n', " ".join(payload).encode())

# 2. Enc(0) 및 Enc(Flag) 획득
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'message> ', b'0' * 32)
r.recvuntil(b'enc> ')
enc_zero = bytes.fromhex(r.recvline().decode().strip())

r.sendlineafter(b'> ', b'2')
r.recvuntil(b'flag> ')
enc_flag = bytes.fromhex(r.recvline().decode().strip())

# 3. 128개의 기저 벡터(Basis) 수집
log.info("Step 2: Collecting basis vectors...")
basis = []
for i in range(16):
    for j in range(8):
        p = bytearray(16)
        p[i] = (1 << j)
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'message> ', p.hex().encode())
        r.recvuntil(b'enc> ')
        res = bytes.fromhex(r.recvline().decode().strip())
        basis.append(xor(res, enc_zero))

# 4. 행렬 방정식 M * x = T 풀이 (방향 수정됨!)
def solve_linear_system(basis_vectors, target_bytes):
    # 128x128 행렬 M 생성 (열 방향으로 삽입)
    mat = [[0]*128 for _ in range(128)]
    for k in range(128): # k는 변수 인덱스 (입력 비트)
        for m in range(128): # m은 방정식 인덱스 (출력 비트)
            byte_idx = m // 8
            bit_idx = m % 8
            mat[m][k] = (basis_vectors[k][byte_idx] >> bit_idx) & 1

    # 타겟 T 생성
    t = [0] * 128
    for m in range(128):
        byte_idx = m // 8
        bit_idx = m % 8
        t[m] = (target_bytes[byte_idx] >> bit_idx) & 1

    # 가우스 소거법 (Gaussian Elimination)
    n = 128
    for j in range(n):
        pivot = j
        while pivot < n and mat[pivot][j] == 0:
            pivot += 1
        if pivot == n: continue

        # 행 스왑
        mat[j], mat[pivot] = mat[pivot], mat[j]
        t[j], t[pivot] = t[pivot], t[j]

        # 소거
        for i in range(n):
            if i != j and mat[i][j] == 1:
                for k in range(j, n):
                    mat[i][k] ^= mat[j][k]
                t[i] ^= t[j]

    # 결과 비트 t를 바이트 배열로 조립
    res_bytes = bytearray(16)
    for j in range(128):
        if t[j]:
            res_bytes[j // 8] |= (1 << (j % 8))
    return res_bytes

# 5. 복호화 실행
log.info("Step 3: Solving matrix equation...")
full_flag = b""
# 플래그가 여러 블록일 수 있으므로 16바이트씩 잘라서 해독
for i in range(0, len(enc_flag), 16):
    block = enc_flag[i:i+16]
    if len(block) == 16:
        target = xor(block, enc_zero)
        full_flag += solve_linear_system(basis, target)

log.success("Exploit Complete!")
print("-" * 50)
print(f"Decoded: {full_flag}")
# 깔끔한 문자열 출력
clean_flag = ''.join([chr(b) for b in full_flag if 32 <= b <= 126])
print(f"Flag String: {clean_flag}")
print("-" * 50)

r.close()