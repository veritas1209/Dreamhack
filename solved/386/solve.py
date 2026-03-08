from pwn import *
from base64 import b64decode, b64encode

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# 서버 접속 (IP와 포트는 실제 환경에 맞게 수정하세요)
r = remote('host3.dreamhack.games', 22650)

# 1. 'test Command' 암호문 받아오기
r.recvuntil(b'test Command: ')
test_b64 = r.recvline().strip()
test_cipher = b64decode(test_b64)

# test_cipher 구조: IV(16) + C1~C10(160) + C11(16) = 총 192바이트
# 2. C10 (10번째 암호문 블록) 추출 (인덱스 160 ~ 176)
c10 = test_cipher[160:176]

# 3. 오라클에 요청할 메시지 생성
# P'_{11} = b'show' + 패딩(\x0c) 12바이트
target_p11 = b'show' + b'\x0c' * 12
oracle_msg = xor(target_p11, c10)

# 4. Cipher Oracle을 이용해 C'_{11} 생성
r.recvuntil(b'IV...: ')
r.sendline(b64encode(b'\x00' * 16)) # IV 영향 제거를 위해 Null byte 전송
r.recvuntil(b'Message...: ')
r.sendline(b64encode(oracle_msg))

# 5. 오라클 결과 받아오기
r.recvuntil(b'Ciphertext:')
oracle_b64 = r.recvline().strip()
oracle_resp = b64decode(oracle_b64)

# 6. 새로 만들어진 C'_{11} 블록 추출 (앞의 16바이트 IV 제거 후 첫 블록)
oracle_c1 = oracle_resp[16:32]

# 7. 페이로드 조립: 원본 토큰 암호문(IV ~ C10) + 조작된 C'_{11}
payload = test_cipher[:176] + oracle_c1

# 8. 최종 페이로드 전송
r.recvuntil(b'Enter your command: ')
r.sendline(b64encode(payload))

# 9. 결과 확인: 서버가 보내는 모든 응답을 날것 그대로 화면에 출력!
r.interactive()