from Crypto.Util.Padding import unpad

def xor_bytes(a, b, c=None):
    if c:
        return bytes([_a ^ _b ^ _c for _a, _b, _c in zip(a, b, c)])
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

def solve():
    # 1. 파일 읽기
    try:
        with open('blizzard_report.pdf.enc', 'rb') as f:
            report_enc = f.read()
        with open('frozen_flag.enc', 'rb') as f:
            flag_enc = f.read()
    except FileNotFoundError:
        print("Error: Encrypted files not found.")
        return

    # -----------------------------------------------------------
    # Step 1: Keystream (K) 복구하기
    # (이전과 동일한 로직: A 블록을 이용해 키스트림 복구)
    # -----------------------------------------------------------
    known_A_block = b'A' * 16
    keystreams = {} 
    
    found_start_index = -1
    
    for i in range(16, len(report_enc) - 32, 16):
        c_curr = report_enc[i : i+16]
        c_prev = report_enc[i-16 : i]
        k_candidate = xor_bytes(c_curr, c_prev, known_A_block)
        
        if i + 256 + 16 <= len(report_enc):
            i_next_cycle = i + 256
            c_next = report_enc[i_next_cycle : i_next_cycle+16]
            c_next_prev = report_enc[i_next_cycle-16 : i_next_cycle]
            k_check = xor_bytes(c_next, c_next_prev, known_A_block)
            
            if k_candidate == k_check:
                # 키스트림 복구
                current_block_idx = (i // 16) % 16
                for offset in range(16):
                    idx = i + offset * 16
                    block_k_idx = (idx // 16) % 16
                    c_b = report_enc[idx : idx+16]
                    c_p = report_enc[idx-16 : idx]
                    keystreams[block_k_idx] = xor_bytes(c_b, c_p, known_A_block)
                
                # 'A' 구간의 시작점 찾기 (역추적)
                temp_i = i
                while temp_i >= 16:
                    prev_i = temp_i - 16
                    block_idx = (prev_i // 16) % 16
                    c_curr = report_enc[prev_i : prev_i+16]
                    c_prev = report_enc[prev_i-16 : prev_i]
                    
                    decrypted_permuted = xor_bytes(c_curr, c_prev, keystreams[block_idx])
                    if decrypted_permuted == b'A' * 16:
                        temp_i = prev_i
                    else:
                        found_start_index = temp_i # 여기가 A의 시작 (즉, 앞은 P가 섞여있음)
                        break
                break

    if len(keystreams) != 16:
        print("[-] Failed to recover keystreams.")
        return

    print(f"[+] Recovered all 16 Keystreams.")
    print(f"[+] 'A' block starts at index: {found_start_index}")

    # -----------------------------------------------------------
    # Step 2: Shuffle Map (_t) 복구하기 (Split P 대응)
    # Block 0: Header(??) + P_head
    # Block 1: P_tail + A_head (여기가 found_start_index - 16 일 것임)
    # -----------------------------------------------------------
    
    # Block 1 (P의 뒷부분이 포함된 블록) 분석
    # found_start_index는 A만 나오는 첫 블록. 그 바로 앞 블록(Block 1)은 섞여있음.
    idx_1 = found_start_index - 16
    idx_0 = idx_1 - 16
    
    # Decrypt Block 1 (Raw Shuffled Bytes)
    c_1 = report_enc[idx_1 : idx_1+16]
    c_0 = report_enc[idx_0 : idx_0+16] # IV 역할
    k_1 = keystreams[(idx_1 // 16) % 16]
    dec_1 = xor_bytes(c_1, c_0, k_1) # Shuffled(P_tail + A...)

    # Decrypt Block 0 (Raw Shuffled Bytes)
    c_neg1 = b'\x00' * 16 # IV for first block
    k_0 = keystreams[(idx_0 // 16) % 16]
    dec_0 = xor_bytes(c_0, c_neg1, k_0) # Shuffled(Header + P_head)

    P_original = b"0123456789abcdef"
    
    # Block 1에 P 문자가 몇 개 있는지 확인하여 정렬 상태 파악
    p_chars_in_dec1 = [c for c in dec_1 if c in P_original]
    
    len_p_tail = len(p_chars_in_dec1)
    len_p_head = 16 - len_p_tail
    
    print(f"[+] Detected P split: Head={len_p_head} bytes, Tail={len_p_tail} bytes")
    
    p_head_bytes = P_original[:len_p_head]
    p_tail_bytes = P_original[len_p_head:]
    
    # Shuffle Map 복구
    # t[i] = 원본 위치
    # 원본 구조:
    # Input_1: [P_tail (0 ~ len_tail-1)] + [A (len_tail ~ 15)]
    # Input_0: [Header (0 ~ 15-len_head)] + [P_head (16-len_head ~ 15)]
    
    t_map = [-1] * 16
    
    for i in range(16):
        char_1 = dec_1[i]
        char_0 = dec_0[i]
        
        # Rule 1: dec_1[i]가 P의 일부라면, 이는 P_tail의 특정 문자임
        if char_1 in p_tail_bytes:
            # P_tail 내에서의 인덱스
            p_idx = p_tail_bytes.index(char_1)
            # Input_1 에서의 위치는 0부터 시작
            t_map[i] = p_idx
            
        # Rule 2: dec_0[i]가 P의 일부라면, 이는 P_head의 특정 문자임
        # 단, dec_1[i]가 'A'일 때만 이 로직을 신뢰 (충돌 방지 및 A 구역 매핑)
        elif char_0 in p_head_bytes:
            # P_head 내에서의 인덱스
            p_idx = p_head_bytes.index(char_0)
            # Input_0 에서의 위치는 뒤쪽 (Header 다음)
            # 위치 = (16 - len_p_head) + p_idx
            # 이는 곧 Input_1 에서 'A'가 시작되는 위치(len_p_tail) + p_idx 와 동일 (수치적으로)
            t_map[i] = (16 - len_p_head) + p_idx

    print(f"[+] Recovered shuffle map: {t_map}")
    
    if -1 in t_map:
        print("[-] Error: Could not fully recover shuffle map.")
        return

    # -----------------------------------------------------------
    # Step 3: Flag 복호화
    # -----------------------------------------------------------
    decrypted_flag = b""
    prev_block = b"\x00" * 16
    
    for i in range(0, len(flag_enc), 16):
        curr_block = flag_enc[i : i+16]
        k_idx = (i // 16) % 16
        
        # 1. XOR Layer
        permuted_m = xor_bytes(curr_block, prev_block, keystreams[k_idx])
        
        # 2. Unshuffle
        # 복호화: Input[t[k]] = Output[k] => original[t[i]] = permuted[i]
        original_m_arr = [0] * 16
        for k in range(16):
            target_idx = t_map[k]
            original_m_arr[target_idx] = permuted_m[k]
            
        decrypted_flag += bytes(original_m_arr)
        prev_block = curr_block

    try:
        flag = unpad(decrypted_flag, 16)
        print(f"\n[+] Flag: {flag.decode('utf-8', errors='ignore')}")
    except Exception as e:
        print(f"\n[-] Padding Error: {e}")
        print(f"Raw: {decrypted_flag}")

if __name__ == "__main__":
    solve()