import base64
import struct
import random
from pwn import *

# --- MT19937 Untempering Functions ---
def untemper(y):
    """MT19937의 Tempering 과정을 역으로 수행하여 내부 상태값을 복구합니다."""
    # Reverse y = y ^ (y >> 18)
    y ^= (y >> 18)
    
    # Reverse y = y ^ ((y << 15) & 0xefc60000)
    y ^= ((y << 15) & 0xefc60000)
    
    # Reverse y = y ^ ((y << 7) & 0x9d2c5680)
    # 7비트씩 왼쪽으로 이동하며 마스킹되므로 5단계를 거쳐 복구
    temp = y
    for _ in range(5):
        temp = y ^ ((temp << 7) & 0x9d2c5680)
    y = temp
    
    # Reverse y = y ^ (y >> 11)
    # 11비트씩 오른쪽으로 이동하므로 3단계를 거쳐 복구
    temp = y
    for _ in range(3):
        temp = y ^ (temp >> 11)
    y = temp
    
    return y & 0xffffffff

# --- Helper Functions ---
def b64u_dec_u32(s):
    """서버의 b64u_enc_u32를 역으로 수행"""
    s = s.strip()
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    raw = base64.urlsafe_b64decode((s + pad).encode())
    return struct.unpack(">I", raw)[0]

def b64u_enc_u32(x):
    """로컬에서 정답을 보낼 때 사용"""
    raw = struct.pack(">I", x & 0xFFFFFFFF)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

# --- Exploit Main ---
# 서버 주소와 포트에 맞게 수정하세요.
io = remote('host8.dreamhack.games', 9416) 
#io = process(['python3', 'chall.py']) # 로컬 테스트용

print("[*] 624개의 토큰 수집을 시작합니다...")
collected_states = []

for i in range(1, 625):
    io.sendlineafter(b"> ", b"1")
    line = io.recvline().decode().strip()
    # "Token[001]: XXXX" 형식에서 XXXX만 추출
    token_str = line.split(": ")[1]
    
    val = b64u_dec_u32(token_str)
    state = untemper(val)
    collected_states.append(state)
    
    if i % 100 == 0:
        print(f"[DEBUG] {i}/624 수집 완료... (Last val: {val:#010x}, State: {state:#010x})")

print("[*] 모든 상태값을 수집했습니다. 내부 상태를 재구성합니다.")

# 파이썬 random 모듈의 상태 구조: (3, (624개의 정수, 624), None)
# 마지막 624는 현재 인덱스를 의미하며, 624개 출력이 끝났으므로 다음 호출 시 twist가 발생하도록 설정
target_state = (3, tuple(collected_states + [624]), None)
predicted_rng = random.Random()
predicted_rng.setstate(target_state)

print("[*] 다음 난수를 예측합니다.")
predicted_val = predicted_rng.getrandbits(32)
predicted_token = b64u_enc_u32(predicted_val)

print(f"[DEBUG] 예측된 32비트 값: {predicted_val} ({predicted_val:#010x})")
print(f"[DEBUG] 제출할 토큰: {predicted_token}")

# 정답 제출
io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Next token: ", predicted_token.encode())

print("[*] 결과 확인:")
print(io.recvall().decode())