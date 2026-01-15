from pwn import *
from functools import reduce

# 2. 슬롯 길이 (분석한 값)
moduli = [73, 83, 89, 97, 103, 79, 101, 127, 131, 137]
remainders = [None] * 10  # 각 슬롯이 언제 '7'이 되는지 저장할 리스트

# --- CRT 구현 (라이브러리 없이) ---
def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def modinv(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1: raise Exception('Modular inverse does not exist')
    return x % m

def chinese_remainder_theorem(remainders, moduli):
    sum = 0
    prod = reduce(lambda x, y: x * y, moduli)
    for r_i, m_i in zip(remainders, moduli):
        p = prod // m_i
        sum += r_i * modinv(p, m_i) * p
    return sum % prod
# -------------------------------

# ... (이전 코드의 Imports 및 설정, CRT 함수들은 동일) ...
# ... (get_lcm, moduli, extended_gcd 등등) ...

def solve():
    # 1. 초기화 및 스캔 (이전과 동일)
    p = remote('host8.dreamhack.games', 19833) # 포트 번호 확인 필요
    p.sendlineafter(b'> ', b'1')
    p.recvuntil(b'slot generated !')
    
    remainders = [None] * 10
    current_rotation = 0
    
    print("[*] Scanning slots...")
    while not all(x is not None for x in remainders):
        p.sendlineafter(b'> ', b'2')
        p.sendlineafter(b'> ', b'1')
        current_rotation += 1
        
        p.recvuntil(b'Result: ')
        line = p.recvline().decode().strip()
        slots = line.split(' ')
        
        for i in range(10):
            if slots[i] == '7' and remainders[i] is None:
                remainders[i] = current_rotation
                # print(f"[+] Found Slot {i}: Needs {current_rotation}")

    print("[*] Scan complete! Calculating answer using CRT...")
    
    # 2. CRT 계산 (이전과 동일)
    target_rotation = chinese_remainder_theorem(remainders, moduli)
    
    # 목표값에서 현재 돌린 횟수를 뺌
    final_input = target_rotation - current_rotation
    
    # 음수 보정
    total_product = reduce(lambda x, y: x * y, moduli)
    while final_input < 0:
        final_input += total_product

    print(f"[*] Total required rotation: {final_input}")

    # === [수정된 부분] ===
    # 3. 쪼개서 보내기 (Chunking)
    # 안전하게 10^18 (1000000000000000000) 단위로 잘라서 보냄
    CHUNK_SIZE = 10**18 
    
    while final_input > 0:
        to_send = min(final_input, CHUNK_SIZE)
        
        print(f"[*] Sending chunk: {to_send}")
        p.sendlineafter(b'> ', b'2')
        p.sendlineafter(b'> ', str(to_send).encode())
        
        # 마지막 Chunk를 보냈을 때 결과 확인
        if to_send == final_input:
             # 결과 출력은 interactive에서 확인하거나 여기서 recvline으로 확인 가능
             pass
             
        final_input -= to_send

    print("[*] All chunks sent! Check for Jackpot.")
    p.interactive()

if __name__ == "__main__":
    solve()