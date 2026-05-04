from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
import ast

# 서버 접속 정보 (문제의 host, port 사용)
host = 'host8.dreamhack.games'
port = 20928
r = remote(host, port)

# 1. Get Info: q 값과 token 가져오기
print("[*] 1. Get Info: q 및 token 정보 추출 중...")
r.recvuntil(b"[3] Get Info\n")
r.sendline(b"3")

r.recvuntil(b"q = ")
q = int(r.recvline().strip())

r.recvuntil(b"token = ")
token_raw = r.recvline().strip().decode()
# 서버가 b'...' 형태로 출력하므로 안전하게 바이트 객체로 파싱
token = ast.literal_eval(token_raw)

print(f"[+] q = {q}")
print(f"[+] token = {token}")

# 2. 메시지 조작: m' = token + q
print("\n[*] 2. 해시 충돌 메시지 생성 중...")
token_int = bytes_to_long(token)
m_prime_int = token_int + q
m_prime_bytes = long_to_bytes(m_prime_int)

# 3. Sign: 위조된 메시지로 서명 획득
print("[*] 3. 조작된 메시지로 서명(Sign) 요청 중...")
r.recvuntil(b"[3] Get Info\n")
r.sendline(b"1")
r.sendlineafter(b"Input message (hex): ", m_prime_bytes.hex().encode())

# 서버가 출력한 (r, s) 튜플 파싱
sig_line = r.recvline().strip().decode()
r_val, s_val = ast.literal_eval(sig_line)
print(f"[+] 획득한 서명 - r: {r_val}")
print(f"[+] 획득한 서명 - s: {s_val}")

# 4. Verify: 원본 token과 획득한 서명으로 검증 우회
print("\n[*] 4. 원본 token에 대한 검증(Verify) 시도 중...")
r.recvuntil(b"[3] Get Info\n")
r.sendline(b"2")
r.sendlineafter(b"Input message (hex): ", token.hex().encode())

# 요구하는 포맷(r, s as decimal integer)에 맞게 쉼표로 구분하여 전송
r.sendlineafter(b"Input signagure (r, s as decimal integer): ", f"{r_val}, {s_val}".encode())

# 플래그 출력 확인
r.recvuntil(b"Signature verification success\n")
flag = r.recvline().strip().decode()

print(f"\n[🎉] FLAG FOUND: {flag}")

r.close()