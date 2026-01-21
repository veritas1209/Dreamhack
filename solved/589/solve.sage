import string
import sys

# 1. 문제 데이터
N = 0x12376eadc9b0bd1f13fa9d904f5a1a75bb7ddaaa77ec5b1e8dec4cb7532b662fcc63a0dfa982e1702be449c9b295bf7a0b7c6ba3dc7aaf3856d681601e723aa3bce3e0cd064793a9c6b00eb01d3e3f0fbceddb208cba2598d9d6a35f3cf8623a1389686807fb5f8f53dd0a7f544c02d030f498f7aa315b7547783399bc88cd3e2859b6786b858a35593537ead5a0cc48401a24cefe6ac6997035f6571af098d5d5b24313437fd89d22cce7fa5907d73c219b609eeea9bcffab0f18504e1d2ed5669752e21dd17b57ea5cf6e6efa76cd965e4589539dc087e152fb4d3f1f90edcdcab22b71b326a3e7e0674f8820a24aa3be15756db2e908d434b80419061bf45
e = 0x10001
p_redacted = 0x50b4040146040415a04084000094153182141460200401063040440024200046055600042240040410248014e00410444640240166000001e09141101084025181052000c30004260000406100601226058401613084a0040492001040404620100401344612000215221412811086840005d06001060000008460040025000
p_mask = 0x1250b70401c6444455a8418d2800945d3182dc1c7060a4010630c0c4282c2a0047575e8084aa4207ac592ca034e02e78445640f40366020089e0b9791119940b53818d2842c3082ea70818e0610a601b2e35844169708ca00404931912e04046e01004893e4632c80a1da23c9ab310868d402dd0600307283300cd680c1a25602
q_redacted = 0x80902304402050a7145440048082208004041205b60014000102340106007002a240b0108404005604000190060092010010004504c2104002100140009020270500022101530484551206642004c1424200000202040042210204c4143704000480101004809114629230312040040000600400420520943204412216404
q_mask = 0x1aa0809033046833d9e7945e420480822090ac0c1a35bf00b48a21223c23060070c2a240b0328c4c235e0408819817209a11531101c50cd21a6012309b40c292302f05000221c353a5845f126e65210ec9c24a0001820284004bf1a206c45637b4500680581894d0d1d46bb2b039a2e84d008a604508420d219c32166b2276c04
ct = 0x97090fc71e4c4c7fe52fb9c5cafde7bae8cf5f911c2755174f3a61515f475c7000d127e23ad99498bd58078abe2890fe40c64067116c66be74ac5422e731905103f4ecc4ae6cf9478580d6fb373744b897caf2b95f01531b626afb46eb88c0f5f419635a27f903ab8ffc55094e015008cbb9520f07755da279226fefa8859bfef694b86ca3fdf88042361d18ecb7ae1ecf98041140b3f167687f45e3da914ee35f9d345782438018310da609578a1047a99a9c54ff846eb2017ac26a0cfb8f5e542c0c7feba904e0ff15a6e2712c2135f9c80b057185cd31a8e9e5371194d063776bdf3537837c705d3761dd6f0ec9419034c294914015bc0e3fbea474fdc15

# SageMath 타입 변환
N = Integer(N)
e = Integer(e)
p_redacted = Integer(p_redacted)
p_mask = Integer(p_mask)
q_redacted = Integer(q_redacted)
q_mask = Integer(q_mask)
ct = Integer(ct)

# 허용된 문자 집합 정의 (문제 조건)
ALLOWED_CHARS = set(string.ascii_letters + "{}_")

def solve():
    candidates = [(0, 0)] # (p, q)
    
    # 0 ~ 1023 비트 순회
    for k in range(1024):
        next_candidates = []
        
        # 현재 비트가 바이트 내에서 몇 번째인지 확인 (0~7)
        # 0: LSB, 7: MSB
        bit_idx = k % 8
        
        # 1. p의 가능한 비트 구하기
        p_opts = []
        # Constraint 1: Bit 7 (MSB) -> 항상 0
        if bit_idx == 7:
            p_opts = [0]
        # Constraint 2: Bit 6 -> 항상 1 (문자 범위 0x41 ~ 0x7D)
        elif bit_idx == 6:
            p_opts = [1]
        else:
            # Mask 확인
            if (p_mask >> k) & 1:
                p_opts = [(p_redacted >> k) & 1]
            else:
                p_opts = [0, 1]

        # 2. q의 가능한 비트 구하기 (동일 로직)
        q_opts = []
        if bit_idx == 7:
            q_opts = [0]
        elif bit_idx == 6:
            q_opts = [1]
        else:
            if (q_mask >> k) & 1:
                q_opts = [(q_redacted >> k) & 1]
            else:
                q_opts = [0, 1]
        
        # 모듈러 마스크 (검증용)
        mod_mask = (1 << (k + 1)) - 1
        target_mod = N & mod_mask
        
        for cur_p, cur_q in candidates:
            for p_bit in p_opts:
                for q_bit in q_opts:
                    next_p = cur_p | (p_bit << k)
                    next_q = cur_q | (q_bit << k)
                    
                    # 3. Branch and Prune (N check)
                    if (next_p * next_q) & mod_mask == target_mod:
                        
                        # 4. 문자열 유효성 검사 (바이트가 완성되는 시점: bit_idx == 7)
                        if bit_idx == 7:
                            # 방금 완성된 바이트 추출 (비트 순서 주의: big endian flag -> int)
                            # 정수는 Little Endian 처럼 쌓이지만, 문자열 변환 시 순서 고려 필요
                            # p = flag[0]...flag[127] -> int conversion
                            # 여기서는 하위 비트부터 채우고 있으므로, flag의 '마지막' 문자부터 복구됨
                            
                            p_byte_val = (next_p >> (k - 7)) & 0xFF
                            q_byte_val = (next_q >> (k - 7)) & 0xFF
                            
                            # 추출된 바이트가 허용된 문자인지 확인
                            if chr(p_byte_val) not in ALLOWED_CHARS:
                                continue
                            if chr(q_byte_val) not in ALLOWED_CHARS:
                                continue
                        
                        next_candidates.append((next_p, next_q))
        
        candidates = next_candidates
        
        if not candidates:
            print(f"Error: No candidates at bit {k}")
            return
            
        if k % 128 == 0:
            print(f"[*] Bit {k}/1024 processed, Candidates: {len(candidates)}")

    print(f"[*] Search complete. Total candidates: {len(candidates)}")
    
    from Crypto.Util.number import long_to_bytes, inverse
    
    for p_found, q_found in candidates:
        if p_found * q_found == N:
            print("[+] Valid p, q found!")
            
            # 1. CT 복호화 (가짜 플래그 확인용)
            phi = (p_found - 1) * (q_found - 1)
            d = inverse(e, phi)
            pt = pow(ct, d, N)
            print(f"[+] Decrypted CT: {long_to_bytes(pt).decode()}")

            # 2. 진짜 플래그 복구 (p와 q 합치기)
            real_flag = long_to_bytes(p_found) + long_to_bytes(q_found)
            print(f"\n[+] REAL FLAG: {real_flag.decode()}")
            return
solve()
