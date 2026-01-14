from pwn import *

# 1. 접속
# p = process('./chall') # 로컬
p = remote('host8.dreamhack.games', 8591)

# 2. 페이로드 구성 (p32가 알아서 뒤집어줌)
# int_arr[0] == 0x64726d68
# int_arr[1] == 0x636b3a29
payload = p32(0x64726d68) + p32(0x636b3a29)

# 3. 전송
p.recvuntil("Input: ")
p.sendline(payload)

# 4. 결과 확인
p.interactive()