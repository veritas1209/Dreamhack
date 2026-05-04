from pwn import *

# 서버 정보 설정 (실제 대회 서버 주소와 포트로 변경하세요)
host = 'host8.dreamhack.games' 
port = 11995
r = remote(host, port)

# DES Semi-weak Key 쌍
key1 = "011f011f010e010e"
key2 = "1f011f010e010e01"

print("[*] 1. Key1을 이용해 플래그 암호화 요청...")
r.recvuntil(b"> ")
r.sendline(b"2")
r.recvuntil(b"key(hex)> ")
r.sendline(key1.encode())

r.recvuntil(b"enc_flag(hex)> ")
enc_flag = r.recvline().strip().decode()
print(f"[+] Encrypted Flag: {enc_flag}")

print("[*] 2. Key2를 이용해 암호화된 플래그를 다시 암호화(복호화) 요청...")
r.recvuntil(b"> ")
r.sendline(b"1")
r.recvuntil(b"key(hex)> ")
r.sendline(key2.encode())
r.recvuntil(b"msg(hex)> ")
r.sendline(enc_flag.encode())

r.recvuntil(b"enc(hex)> ")
decrypted_hex = r.recvline().strip().decode()

# 3. 결과 디코딩 및 패딩 제거
decrypted_bytes = bytes.fromhex(decrypted_hex)
print(f"[*] Raw Decrypted Bytes: {decrypted_bytes}")

# 정규표현식이나 단순 출력을 통해 플래그(DH{...}) 추출
# (서버의 패딩 과정 때문에 뒤에 의미 없는 바이트가 추가되어 있을 수 있습니다)
flag = decrypted_bytes.split(b'}')[0] + b'}'
print(f"\n[🎉] FLAG FOUND: {flag.decode('utf-8', errors='ignore')}")

r.close()