import struct

def decrypt_custom(v0, v1, k):
    delta = 0x9e3779b9
    sum_val = (delta * 32) & 0xFFFFFFFF
    
    for _ in range(32):
        # 1. v1 역연산 (0x401323 ~ 0x40137c)
        # v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (k[(sum >> 11) & 3] + sum)
        ecx_v1 = (((v0 << 4) & 0xFFFFFFFF) ^ (v0 >> 5)) + v0
        key_idx_v1 = (sum_val >> 11) & 3
        v1 = (v1 - (ecx_v1 ^ ((k[key_idx_v1] + sum_val) & 0xFFFFFFFF))) & 0xFFFFFFFF
        
        # 2. sum 감소
        sum_val = (sum_val - delta) & 0xFFFFFFFF
        
        # 3. v0 역연산 (0x4012cb ~ 0x40131a)
        # v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (k[sum & 3] + sum)
        ecx_v0 = (((v1 << 4) & 0xFFFFFFFF) ^ (v1 >> 5)) + v1
        key_idx_v0 = sum_val & 3
        v0 = (v0 - (ecx_v0 ^ ((k[key_idx_v0] + sum_val) & 0xFFFFFFFF))) & 0xFFFFFFFF
        
    return v0, v1

# 데이터 설정
key = [0xd5ec45c7, 0xc72bf41b, 0x9457f045, 0x45c7831a]
# movabs rax, 0x1e5cc8f90ebd34d5 -> v0: 0x0ebd34d5, v1: 0x1e5cc8f9
v0_enc, v1_enc = 0x0ebd34d5, 0x1e5cc8f9

d0, d1 = decrypt_custom(v0_enc, v1_enc, key)
res = struct.pack('<II', d0, d1)

print(f"[*] Decrypted: {res.hex().upper()}")
print(f"[*] Expected : 0A0000000D4948")