from pwn import *

# 서버 접속 정보 (문제의 host, port 사용)
host = 'host8.dreamhack.games'
port = 8905
r = remote(host, port)

# 1. 메뉴 2번: 암호화된 플래그 획득
print("[*] 1. Encrypted flag 획득 중...")
r.sendlineafter(b"> ", b"2")
r.recvuntil(b"encrypted flag > ")
enc_flag = r.recvline().strip().decode()
print(f"[+] Encrypted flag: {enc_flag}")

# 2. 메뉴 1번: 연산 조합을 통한 우회 복호화 수행
# Step 1: DDD 모드 적용
print("[*] 2-1. Applying DDD mode...")
r.sendlineafter(b"> ", b"1")
r.sendlineafter(b"send your message(hex) > ", enc_flag.encode())
r.sendlineafter(b"send your mode > ", b"DDD")
r.recvuntil(b"encrypted message > ")
c1 = r.recvline().strip().decode()

# Step 2: EED 모드 적용
print("[*] 2-2. Applying EED mode (Cancellation 1)...")
r.sendlineafter(b"> ", b"1")
r.sendlineafter(b"send your message(hex) > ", c1.encode())
r.sendlineafter(b"send your mode > ", b"EED")
r.recvuntil(b"encrypted message > ")
c2 = r.recvline().strip().decode()

# Step 3: EED 모드 적용 (최종 복호화)
print("[*] 2-3. Applying EED mode (Cancellation 2 & Finalize)...")
r.sendlineafter(b"> ", b"1")
r.sendlineafter(b"send your message(hex) > ", c2.encode())
r.sendlineafter(b"send your mode > ", b"EED")
r.recvuntil(b"encrypted message > ")
flag_hex = r.recvline().strip().decode()

# 3. 결과 디코딩 및 패딩 제거
flag_bytes = bytes.fromhex(flag_hex)
# 서버가 구현한 Custom 패딩(PKCS#7 유사)으로 인해 생긴 쓰레기 값 제거
flag = flag_bytes.split(b'}')[0] + b'}'

print(f"\n[🎉] FLAG FOUND: {flag.decode('utf-8', errors='ignore')}")

r.close()