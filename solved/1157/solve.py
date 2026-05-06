#!/usr/bin/env python3
from pwn import *
import os

try:
    from cipher import ARIA, xor
except ImportError:
    print("[-] Please ensure cipher.py is in the same directory.")
    exit(1)

def solve():
    host = 'host8.dreamhack.games'
    port = 21649
    print(f"[*] Connecting to {host}:{port}")
    r = remote(host, port)

    def get_enc_3(pt: bytes) -> bytes:
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'plaintext(hex)> ', pt.hex().encode())
        r.recvuntil(b'ciphertext(hex)> ')
        return bytes.fromhex(r.recvline().strip().decode())

    def get_enc_any(eks3: bytes, rnd: int, pt: bytes) -> bytes:
        r.sendlineafter(b'> ', b'2')
        r.sendlineafter(b'eks[3](hex)> ', eks3.hex().encode())
        
        # [수정된 부분] 
        # 개행 문자가 없는 'round(1~16)> ' 프롬프트에서 무한 대기하는 것을 방지하기 위해
        # recvline() 대신 recvuntil(b'> ')을 사용합니다.
        res = r.recvuntil(b'> ').decode()
        
        if "To use this feature" in res:
            print(f"\n[-] Server rejected eks[3]: {eks3.hex()}")
            exit(1)
            
        r.sendline(str(rnd).encode())
        r.sendlineafter(b'plaintext(hex)> ', pt.hex().encode())
        r.recvuntil(b'ciphertext(hex)> ')
        return bytes.fromhex(r.recvline().strip().decode())

    def get_flag() -> bytes:
        r.sendlineafter(b'> ', b'3')
        r.recvuntil(b'encrypted_flag(hex)> ')
        return bytes.fromhex(r.recvline().strip().decode())

    print("[*] Generating Inverse S-Box...")
    inv_sbox = []
    for sb in ARIA.sbox:
        inv_sb = [0] * 256
        for idx, val in enumerate(sb):
            inv_sb[val] = idx
        inv_sbox.append(inv_sb)

    # ==========================================
    # Step 1 & 2: 3개의 다른 델타 셋 수집 (P[0], P[1], P[2] 변화)
    # ==========================================
    print("[*] Step 1: Collecting 256 ciphertexts for Delta Set 1 (P[0] varies)...")
    C1_list = []
    for i in range(256):
        pt = bytes([i]) + b'\x00'*15
        C1_list.append(get_enc_3(pt))
        if (i + 1) % 64 == 0: print(f"    [DEBUG] Collected {i+1}/256")

    print("[*] Step 2: Collecting 256 ciphertexts for Delta Set 2 (P[1] varies)...")
    C2_list = []
    for i in range(256):
        pt = b'\x00' + bytes([i]) + b'\x00'*14
        C2_list.append(get_enc_3(pt))
        if (i + 1) % 64 == 0: print(f"    [DEBUG] Collected {i+1}/256")

    print("[*] Step 3: Collecting 256 ciphertexts for Delta Set 3 (P[2] varies)...")
    C3_list = []
    for i in range(256):
        pt = b'\x00'*2 + bytes([i]) + b'\x00'*13
        C3_list.append(get_enc_3(pt))
        if (i + 1) % 64 == 0: print(f"    [DEBUG] Collected {i+1}/256")

    # ==========================================
    # Step 4: ek[3] 복구 (3개 셋의 교집합 추출)
    # ==========================================
    print("[*] Step 4: Recovering ek[3] using Integral Cryptanalysis...")
    ek3_candidates = []
    for j in range(16):
        valid_cands = []
        for g in range(256):
            # Delta Set 1 검사
            sum1 = 0
            for i in range(256): sum1 ^= inv_sbox[j % 4][C1_list[i][j] ^ g]
            if sum1 != 0: continue
            
            # Delta Set 2 검사
            sum2 = 0
            for i in range(256): sum2 ^= inv_sbox[j % 4][C2_list[i][j] ^ g]
            if sum2 != 0: continue

            # Delta Set 3 검사
            sum3 = 0
            for i in range(256): sum3 ^= inv_sbox[j % 4][C3_list[i][j] ^ g]
            if sum3 != 0: continue

            valid_cands.append(g)

        print(f"    [DEBUG] ek[3] Byte {j:02d} candidates: {[hex(x) for x in valid_cands]}")
        if len(valid_cands) != 1:
            print(f"[-] Error: Failed to reduce candidates for byte {j}. Got {len(valid_cands)} candidates.")
            exit(1)
        ek3_candidates.append(valid_cands[0])

    ek3 = bytes(ek3_candidates)
    print(f"[+] Successfully recovered ek[3]: {ek3.hex()}")

    # ==========================================
    # Step 5: ek[0], ek[1] 복구 (round=1)
    # ==========================================
    print("[*] Step 5: Querying Option 2 to recover ek[0] and ek[1] (using r=1)...")
    P1 = b'\x00'*16
    P2 = b'\x01'*16
    P3 = b'\x02'*16
    
    # 여기서 멈추지 않고 정상적으로 넘어갈 것입니다.
    C1_1 = get_enc_any(ek3, 1, P1)
    C1_2 = get_enc_any(ek3, 1, P2)
    C1_3 = get_enc_any(ek3, 1, P3)

    print("    [DEBUG] C1_1 (r=1, P=0x00..):", C1_1.hex())
    print("    [DEBUG] C1_2 (r=1, P=0x01..):", C1_2.hex())
    print("    [DEBUG] C1_3 (r=1, P=0x02..):", C1_3.hex())

    ek0_candidates = []
    for j in range(16):
        cands = []
        for g in range(256):
            v1 = ARIA.sbox[j % 4][P1[j] ^ g]
            v2 = ARIA.sbox[j % 4][P2[j] ^ g]
            v3 = ARIA.sbox[j % 4][P3[j] ^ g]
            if (v1 ^ v2) == (C1_1[j] ^ C1_2[j]) and (v1 ^ v3) == (C1_1[j] ^ C1_3[j]):
                cands.append(g)
        print(f"    [DEBUG] ek[0] Byte {j:02d} candidates: {[hex(x) for x in cands]}")
        ek0_candidates.append(cands[0])
    
    ek0 = bytes(ek0_candidates)
    print(f"[+] Successfully recovered ek[0]: {ek0.hex()}")

    s0_out = bytes([ARIA.sbox[j % 4][P1[j] ^ ek0[j]] for j in range(16)])
    ek1 = xor(C1_1, s0_out)
    print(f"[+] Successfully recovered ek[1]: {ek1.hex()}")

    # ==========================================
    # Step 6: ek[2] 복구 (round=2)
    # ==========================================
    print("[*] Step 6: Querying Option 2 to recover ek[2] (using r=2)...")
    C2_1 = get_enc_any(ek3, 2, P1)
    print("    [DEBUG] C2_1 (r=2, P=0x00..):", C2_1.hex())

    dummy_aria = ARIA(b'\x00'*16, 3)
    state1 = dummy_aria._diffusion(s0_out)
    print("    [DEBUG] state1 (after r=1 diffusion):", state1.hex())

    sub1_in = xor(state1, ek1)
    sub1_out = bytes([ARIA.sbox[(j + 2) % 4][sub1_in[j]] for j in range(16)])
    ek2 = xor(C2_1, sub1_out)
    print(f"[+] Successfully recovered ek[2]: {ek2.hex()}")

    # ==========================================
    # Step 7: 플래그 복호화
    # ==========================================
    print("[*] Step 7: Fetching and decrypting the flag...")
    enc_flag = get_flag()
    print(f"    [DEBUG] Encrypted Flag: {enc_flag.hex()}")

    dummy_aria.ek = [ek0, ek1, ek2, ek3] + [b'\x00'*16]*13
    dummy_aria.dk = dummy_aria._dec_key_expansion()
    
    dec_flag = dummy_aria.decrypt(enc_flag)
    print(f"\n[+] FLAG DECRYPTED: {dec_flag.decode('utf-8', errors='ignore')}")

if __name__ == '__main__':
    solve()