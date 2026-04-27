import torch
import numpy as np
import time
import os
from numba import njit

# 큰 상수들을 미리 np.uint32로 래핑하여 float64로 자동 변환되는 것을 철저히 막습니다.
AK = np.uint32(0xFFFFFFFF)

@njit(fastmath=True)
def rol32(x, y):
    x = np.uint32(x)
    y = np.uint32(y) % np.uint32(32)
    if y == 0:
        return x & AK
    return ((x << y) | (x >> (np.uint32(32) - y))) & AK

@njit(fastmath=True)
def f_func(x, y):
    x = np.uint32(x)
    y = np.uint32(y)
    _0 = x + np.uint32(1)
    _1 = np.uint32(2654435761) + y * np.uint32(16909060)
    _2 = _0 * _1 + y * np.uint32(2779096485)
    return _2 & AK

@njit(fastmath=True)
def calc_F(x1, x2, x3, t, n_adj, ah, aa, ab, ac, ad, ae, af):
    x1, x2, x3 = np.uint32(x1), np.uint32(x2), np.uint32(x3)
    t, n_adj = np.uint32(t), np.uint32(n_adj)
    ah = np.uint32(ah)
    
    r5 = (n_adj ^ np.uint32(727)) & np.uint32(1023)
    r6 = (n_adj * np.uint32(405)) & AK
    r6 = (r6 + np.uint32(173)) & AK
    r6 = r6 & np.uint32(1023)
    
    r7 = (n_adj * np.uint32(741)) & AK
    r7 = (r7 + np.uint32(697)) & AK
    r7 = r7 & np.uint32(1023)
    
    r8 = n_adj >> np.uint32(5)
    r8 = (r8 + n_adj) & AK
    r8 = r8 ^ np.uint32(877)
    r8 = r8 & np.uint32(1023)
    
    r9 = (n_adj * np.uint32(933)) & AK
    r9 = (r9 + np.uint32(499)) & AK
    r9 = r9 & np.uint32(1023)
    
    r11 = np.uint32(aa[r5])
    r10 = (x2 + r11) & AK
    r10 = (r10 + t) & AK
    r11 = (n_adj * np.uint32(2654435769)) & AK
    r10 = (r10 + r11) & AK
    r11 = x3 >> np.uint32(13)
    r11 = (r10 ^ r11) & np.uint32(255)
    r12 = np.uint32(af[r11])
    
    r13 = r10 ^ x3
    r13 = (r13 + r12) & AK
    r11 = np.uint32(ab[r6])
    r13 = (r13 + r11) & AK
    
    r11 = np.uint32(ad[r8])
    r13 = rol32(r13, r11)
    
    r11 = np.uint32(ac[r7])
    r14 = (x1 + r11) & AK
    r14 = r14 ^ r13
    r14 = (r14 * ah) & AK
    
    r15 = (x3 + r12) & AK
    r15 = (r15 + t) & AK
    r11 = np.uint32(ae[r9])
    r15 = rol32(r15, r11)
    
    r11 = np.uint32(ac[r7])
    r16 = (r14 + r11) & AK
    r16 = r16 ^ r15
    return r16 & AK

@njit(fastmath=True)
def e_inv(y0, y1, y2, y3, tweak, ah, aa, ab, ac, ad, ae, af, lim):
    y0, y1, y2, y3 = np.uint32(y0), np.uint32(y1), np.uint32(y2), np.uint32(y3)
    tweak = np.uint32(tweak)
    
    for i in range(lim - 1, -1, -1):
        n_base = np.uint32(i * 3)
        
        n_adj = n_base + np.uint32(2)
        x0 = y3 ^ calc_F(y0, y1, y2, tweak, n_adj, ah, aa, ab, ac, ad, ae, af)
        x1, x2, x3 = y0, y1, y2
        y0, y1, y2, y3 = x0, x1, x2, x3
        
        n_adj = n_base + np.uint32(1)
        x0 = y3 ^ calc_F(y0, y1, y2, tweak, n_adj, ah, aa, ab, ac, ad, ae, af)
        x1, x2, x3 = y0, y1, y2
        y0, y1, y2, y3 = x0, x1, x2, x3
        
        n_adj = n_base + np.uint32(0)
        x0 = y3 ^ calc_F(y0, y1, y2, tweak, n_adj, ah, aa, ab, ac, ad, ae, af)
        x1, x2, x3 = y0, y1, y2
        y0, y1, y2, y3 = x0, x1, x2, x3
        
    return y0, y1, y2, y3

@njit(fastmath=True)
def decrypt_all_blocks(enc_ints, num_blocks, s00, s10, s20, s30, ah, aa, ab, ac, ad, ae, af, lim):
    s00, s10, s20, s30 = np.uint32(s00), np.uint32(s10), np.uint32(s20), np.uint32(s30)
    ah = np.uint32(ah)
    
    decrypted_ints = np.zeros(num_blocks * 4, dtype=np.uint32)
    
    for n in range(num_blocks):
        n_u32 = np.uint32(n)
        y0 = np.uint32(enc_ints[n*4 + 0])
        y1 = np.uint32(enc_ints[n*4 + 1])
        y2 = np.uint32(enc_ints[n*4 + 2])
        y3 = np.uint32(enc_ints[n*4 + 3])
        
        # 1. Tweak(z) 계산
        _0 = (s00 + rol32(s10, np.uint32(7))) & AK
        _1 = _0 ^ (s20 ^ s30)
        _2 = (_1 + n_u32 * np.uint32(1779033703)) & AK
        z = _2 & AK
        
        # 2. 파이스텔 역연산
        x0, x1, x2, x3 = e_inv(y0, y1, y2, y3, z, ah, aa, ab, ac, ad, ae, af, lim)
        
        # 3. 평문 추출
        q0 = x0 ^ s00 ^ f_func(n_u32, np.uint32(0))
        q1 = x1 ^ s10 ^ f_func(n_u32, np.uint32(1))
        q2 = x2 ^ s20 ^ f_func(n_u32, np.uint32(2))
        q3 = x3 ^ s30 ^ f_func(n_u32, np.uint32(3))
        
        decrypted_ints[n*4 + 0] = q0
        decrypted_ints[n*4 + 1] = q1
        decrypted_ints[n*4 + 2] = q2
        decrypted_ints[n*4 + 3] = q3
        
        # 4. 다음 블록을 위한 State 업데이트 (체이닝)
        s01 = (y0 + rol32(q1 ^ s20, np.uint32(3)) + n_u32) & AK
        s11 = y1 ^ rol32((q2 + s30) & AK, np.uint32(11))
        s21 = (y2 + (q3 ^ s01) + np.uint32(3144134277)) & AK
        s31 = ((y3 + q0) ^ rol32(s11, np.uint32(17))) & AK
        
        s00, s10, s20, s30 = s01, s11, s21, s31
        
        # 진행상황 출력
        if (n + 1) % 5000 == 0:
            print("[Numba] Decoded blocks:", n + 1, "/", num_blocks)
            
    return decrypted_ints

def solve(model_path, enc_path, out_path):
    print(f"[DEBUG] === 최종 복호화 프로세스 시작 ===")
    
    print("[DEBUG] 1. 모델에서 키 배열 및 S-Box 로드 중...")
    model = torch.jit.load(model_path, map_location='cpu')
    
    # Numba 호환성을 위해 Numpy 배열(uint32)로 변환
    ah = int(model.ah.item())
    aa = model.aa.numpy().astype(np.uint32)
    ab = model.ab.numpy().astype(np.uint32)
    ac = model.ac.numpy().astype(np.uint32)
    ad = model.ad.numpy().astype(np.uint32)
    ae = model.ae.numpy().astype(np.uint32)
    af = model.af.numpy().astype(np.uint32)
    ag = model.ag.numpy().astype(np.uint32)
    s00, s10, s20, s30 = ag[0], ag[1], ag[2], ag[3]
    
    lim = len(aa)*256 + len(af)*512 + len(ag)*10922 + 3
    print(f"[DEBUG] - 계산된 라운드 수 (lim): {lim}")
    
    print(f"[DEBUG] 2. 암호화된 파일 읽는 중: {enc_path}")
    with open(enc_path, 'rb') as f:
        enc_data = f.read()
    
    # 데이터를 32비트 Unsigned Int 배열로 변환
    num_ints = len(enc_data) // 4
    enc_ints = np.frombuffer(enc_data, dtype=np.uint32)
    num_blocks = num_ints // 4
    
    print("[DEBUG] 3. 초고속 Numba 복호화 엔진 가동 (처음 실행 시 JIT 컴파일로 몇 초 걸릴 수 있습니다)...")
    start_time = time.time()
    
    decrypted_ints = decrypt_all_blocks(
        enc_ints, num_blocks, 
        s00, s10, s20, s30, 
        ah, aa, ab, ac, ad, ae, af, lim
    )
    
    elapsed = time.time() - start_time
    print(f"[DEBUG] 4. 복호화 완료! 소요 시간: {elapsed:.2f} 초")
    
    print(f"[DEBUG] 5. 파일로 저장: {out_path}")
    out_bytes = decrypted_ints.tobytes()
    
    with open(out_path, 'wb') as f:
        f.write(out_bytes)
    
    print(f"\n[SUCCESS] 모든 과정이 끝났습니다. {out_path} 파일을 열어 플래그를 확인하세요!")

if __name__ == "__main__":
    solve("model.pt", "teto.png.enc", "teto_recovered.png")