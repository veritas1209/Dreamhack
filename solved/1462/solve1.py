import os
from bitstring import BitArray
from cipher import SPN

# cipher.py에서 S-box와 P-box 가져오기
sbox = SPN.sbox
pbox = SPN.pbox

# S-box 역함수 테이블
sbox_inv = [0] * 256
for i in range(256):
    sbox_inv[sbox[i]] = i

print("[*] LAT(Linear Approximation Table) 계산 중...")
corr_table = [[0.0] * 256 for _ in range(256)]
for x in range(256):
    sx = sbox[x]
    for a in range(256):
        in_parity = bin(x & a).count('1') % 2
        for b in range(256):
            out_parity = bin(sx & b).count('1') % 2
            if in_parity == out_parity:
                corr_table[a][b] += 1

# 각 출력 마스크에 대해 가장 상관계수(Correlation)가 높은 입력 마스크 상위 4개 미리 캐싱
top_in_masks = {}
for b in range(256):
    if b == 0:
        top_in_masks[0] = [(0, 1.0)]
    else:
        possible = []
        for a in range(1, 256):
            c = (corr_table[a][b] - 128) / 128.0
            if c != 0:
                possible.append((a, c))
        possible.sort(key=lambda x: abs(x[1]), reverse=True)
        top_in_masks[b] = possible[:4]

def pbox_mask_backward(m_in_64):
    """P-box 역추적"""
    m_out_64 = 0
    for i in range(64):
        bit_idx_in = pbox[i]
        bit_val = (m_in_64 >> (63 - bit_idx_in)) & 1
        if bit_val:
            m_out_64 |= (1 << (63 - i))
    return m_out_64

def get_best_trail(target_byte):
    """Beam Search를 활용하여 4라운드 전체 최적의 선형 경로 탐색"""
    beam = []
    # 타겟 바이트를 향하는 1~255 마스크를 시작점으로 설정
    for initial_mask in range(1, 256):
        m_post = (initial_mask << (8 * (7 - target_byte)))
        beam.append((m_post, 1.0, m_post)) # (현재 마스크, 상관계수, 초기 타겟 마스크)
        
    for r in range(4):
        next_beam = []
        for m_post, current_corr, initial_m in beam:
            m_pre = pbox_mask_backward(m_post)
            bytes_pre = [(m_pre >> (8*(7-i))) & 0xFF for i in range(8)]
            
            # 8개 바이트의 입력 마스크 조합 생성 (DFS)
            def get_combs(idx):
                if idx == 8:
                    yield (0, 1.0)
                    return
                out_b = bytes_pre[idx]
                for in_b, c in top_in_masks[out_b]:
                    for rest_m, rest_c in get_combs(idx + 1):
                        yield ((in_b << (8*(7-idx))) | rest_m, c * rest_c)
            
            for m_in, c_mult in get_combs(0):
                new_corr = current_corr * c_mult
                if new_corr != 0:
                    next_beam.append((m_in, new_corr, initial_m))
                    
        # 중복 제거 및 상위 100개 경로만 유지 (가지치기)
        unique_beam = {}
        for m_in, c, init_m in next_beam:
            if (m_in, init_m) not in unique_beam or abs(c) > abs(unique_beam[(m_in, init_m)]):
                unique_beam[(m_in, init_m)] = c
        
        sorted_beam = sorted([ (m, c, init_m) for (m, init_m), c in unique_beam.items() ], key=lambda x: abs(x[1]), reverse=True)
        beam = sorted_beam[:100]
        
    if beam:
        best_m_in, best_c, best_init_m = beam[0]
        return (best_m_in, best_init_m), best_c
    return None, 0.0

print("[*] 데이터를 읽는 중...")
pairs = []
with open('data', 'rb') as f:
    while True:
        pt = f.read(8)
        if not pt:
            break
        ct_full = f.read(16)
        if len(ct_full) == 16:
            pairs.append((pt, ct_full[:8]))
print(f"[*] 총 {len(pairs)}개의 Plaintext-Ciphertext 쌍 로드 완료.")

recovered_k5 = []

for target_byte in range(8):
    print(f"\n[*] Round 5 Key의 Byte {target_byte} 복구 중...")
    trail, bias = get_best_trail(target_byte)
    
    if not trail:
        print("[-] 선형 경로를 찾지 못했습니다!")
        exit(1)
        
    p_mask, c_mask = trail
    c_mask_byte = (c_mask >> (8 * (7 - target_byte))) & 0xFF
    
    print(f"    - 최적 경로 상관계수(Correlation): {bias:.6f}")
    
    best_guess = 0
    max_dev = -1
    
    # K5 바이트 브루트포스
    for guess in range(256):
        count = 0
        for pt, ct in pairs:
            p_val = int.from_bytes(pt, 'big') & p_mask
            p_parity = bin(p_val).count('1') % 2
            
            c_byte = ct[target_byte]
            state_byte = sbox_inv[c_byte ^ guess]
            c_parity = bin(state_byte & c_mask_byte).count('1') % 2
            
            if p_parity == c_parity:
                count += 1
                
        dev = abs(count - (len(pairs) // 2))
        if dev > max_dev:
            max_dev = dev
            best_guess = guess
            
    print(f"    - 최대 편차(Deviance): {max_dev}")
    print(f"    => 복구된 K5[{target_byte}]: {hex(best_guess)}")
    recovered_k5.append(best_guess)

print(f"\n[*] 5라운드 키(K5) 전체 복구 완료: {[hex(b) for b in recovered_k5]}")

# 키 스케줄 역산
def reverse_key_expansion(k5_bytes):
    round_keys = [None] * 6
    round_keys[5] = BitArray(bytes=bytes(k5_bytes))

    for r in range(5, 0, -1):
        k_curr = round_keys[r]
        C = [k_curr[i*8:(i+1)*8].uint for i in range(8)]
        P = [0] * 8
        for i in range(7, 0, -1):
            P[i] = C[i] ^ C[i-1]
        p7_rol = ((P[7] << 1) | (P[7] >> 7)) & 0xFF
        T = sbox[p7_rol]
        P[0] = C[0] ^ T
        round_keys[r-1] = BitArray(bytes=bytes(P))
    return round_keys[0].bytes

master_key = reverse_key_expansion(recovered_k5)
print(f"[*] 마스터 키(Master Key) 복구 완료: {master_key.hex()}")

# 플래그 복호화
spn = SPN(master_key)
with open('enc_flag', 'rb') as f:
    enc_flag = f.read()

flag = spn.decrypt(enc_flag)
print(f"\n[+] FLAG: {flag.decode(errors='ignore')}")