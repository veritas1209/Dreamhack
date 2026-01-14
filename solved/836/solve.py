from pwn import *

# 1. 접속 정보 (문제 페이지에서 확인한 포트로 수정하세요!)
# p = process('./prob') # 로컬 테스트용
p = remote('host8.dreamhack.games', 23957) 

# 2. 랜덤 값 파싱
p.recvuntil("Random number: ")
rand_str = p.recvline().strip() # 예: 0x12345678
rand_num = int(rand_str, 16)
log.info(f"Random Number: {hex(rand_num)}")

# 3. 계산 (Target ^ Random)
# Target: "a0b4c1d7"를 뒤집은 "7d1c4b0a"
target_num = 0x7d1c4b0a 
result = target_num ^ rand_num

log.info(f"Target Number: {hex(target_num)}")
log.info(f"Calculated Input: {result}")

# 4. 정답 전송
p.recvuntil("Input? ")
p.sendline(str(result))

# 5. 플래그 확인
p.interactive()