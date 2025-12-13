from pwn import *
from Crypto.Cipher import AES
import hashlib

# 서버 연결
conn = remote('host3.dreamhack.games', 9995)

# Prime 값 받기
conn.recvuntil(b'Prime: ')
prime = int(conn.recvline().strip(), 16)
print(f"Prime: {hex(prime)}")

# Alice의 키 받기
conn.recvuntil(b'Key: ')
alice_original_key = int(conn.recvline().strip(), 16)
print(f"Alice's original key: {hex(alice_original_key)}")

# Alice에게 1을 보내기 (Bob은 shared key = 1을 계산함)
conn.recvuntil(b'>> ')
conn.sendline(b'1')

# Bob의 키 받기
conn.recvuntil(b'Key: ')
bob_original_key = int(conn.recvline().strip(), 16)
print(f"Bob's original key: {hex(bob_original_key)}")

# Bob에게 1을 보내기 (Alice는 shared key = 1을 계산함)
conn.recvuntil(b'>> ')
conn.sendline(b'1')

# 암호화된 flag 받기
conn.recvuntil(b'Alice: ')
alice_encrypted = conn.recvline().strip().decode()
print(f"Alice encrypted: {alice_encrypted}")

conn.recvuntil(b'Bob: ')
bob_encrypted = conn.recvline().strip().decode()
print(f"Bob encrypted: {bob_encrypted}")

# 공유 키는 1이므로, AES 키 생성
shared_key = 1
aes_key = hashlib.md5(str(shared_key).encode()).digest()
cipher = AES.new(aes_key, AES.MODE_ECB)

# 복호화
from Crypto.Util.Padding import unpad

alice_part = unpad(cipher.decrypt(bytes.fromhex(alice_encrypted)), 16)
bob_part = unpad(cipher.decrypt(bytes.fromhex(bob_encrypted)), 16)

flag = alice_part + bob_part
print(f"\nFlag: {flag.decode()}")

conn.close()