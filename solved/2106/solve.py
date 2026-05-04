from pwn import *

# 서버 접속 정보 (문제의 host, port 사용)
host = 'host8.dreamhack.games'
port = 18696
r = remote(host, port)

# 1. 메뉴 3번: 암호화된 플래그 가져오기
print("[*] 1. Encrypted flag 요청 중...")
r.sendlineafter(b"> ", b"3")
r.recvuntil(b"Encrypted flag > ")
enc_flag = r.recvline().strip().decode()
print(f"[+] Encrypted flag (hex): {enc_flag}")

# 2. 메뉴 2번: 더미 키를 이용해 복호화하기
print("[*] 2. Dummy key로 복호화 요청 중...")
r.sendlineafter(b"> ", b"2")
r.recvline() # "My key is not for sell..." 메시지 무시

# 더미 값 전송: 패리티 비트(LSB)만 뒤집기 위해 모두 1을 입력
r.sendline(b"1 1 1 1 1 1 1 1") 

# 암호화된 플래그를 메시지로 전송
r.sendlineafter(b"send your message(hex) > ", enc_flag.encode())

# 복호화된 결과 수신
r.recvuntil(b"encrypted message > ")
decrypted_hex = r.recvline().strip().decode()

# 3. 결과 파싱 (뒤에 붙은 쓰레기 패딩 값 무시)
decrypted_bytes = bytes.fromhex(decrypted_hex)
print(f"[*] Raw decrypted (hex): {decrypted_bytes}")

# '}' 기준으로 잘라서 플래그만 추출
flag = decrypted_bytes.split(b'}')[0] + b'}'
print(f"\n[🎉] FLAG FOUND: {flag.decode('utf-8', errors='ignore')}")

r.close()