from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import os

# --- 문제에서 제공된 stronghash 함수 복사 ---
def stronghash(msg: bytes) -> bytes:
    hashed_msg = pad(msg, 16)
    for _ in "Stronger!!":
        hashed_msg = AES.new(hashed_msg[:16], AES.MODE_ECB).encrypt(hashed_msg)

    # Stronger!!!
    for length in range(2, 16):
        md5 = hashlib.md5(hashed_msg[:length])
        hashed_msg = md5.digest()

    # Stronger!!!!
    for length in range(16, 32):
        sha256 = hashlib.sha256(hashed_msg[:length])
        hashed_msg = sha256.digest()

    return hashed_msg

# --- Solver ---

def solve():
    # 서버 접속 정보 (로컬 테스트용, 실제 서버 주소로 변경 필요)
    # r = process(["python3", "prob.py"]) # 로컬 파일 실행 시
    r = remote("host8.dreamhack.games", 16928) # 예시 주소, 실제 포트로 변경하세요

    # 해시 충돌을 찾기 위한 Rainbow Table (Cache)
    # Key: Hash(hex string), Value: Input(hex string)
    rainbow_table = {}
    
    # 충돌 찾기용 카운터
    collision_counter = 0

    def find_collision(target_hash_hex):
        nonlocal collision_counter
        
        # 이미 찾은 해시라면 바로 반환
        if target_hash_hex in rainbow_table:
            return rainbow_table[target_hash_hex]

        # 찾을 때까지 계속 생성
        while True:
            # 임의의 입력 생성 (단순히 숫자를 증가시키거나 랜덤 바이트 사용)
            # 여기서는 카운터를 바이트로 변환하여 사용
            test_msg = str(collision_counter).encode()
            test_hash = stronghash(test_msg).hex()
            
            # 테이블에 저장 (나중을 위해)
            rainbow_table[test_hash] = test_msg.hex()
            
            collision_counter += 1
            
            # 목표 해시를 찾았으면 반환
            if test_hash == target_hash_hex:
                return test_msg.hex()
            
            # 진행 상황 표시 (선택 사항)
            if collision_counter % 5000 == 0:
                print(f"[*] Pre-computing hashes... count: {collision_counter}, table size: {len(rainbow_table)}")

    # 100 스테이지 반복
    for i in range(100):
        r.recvuntil(f"Stage {i + 1}".encode())
        r.recvuntil(b"My hashed password : ")
        
        # 서버의 해시값 가져오기
        target_hash = r.recvline().strip().decode()
        print(f"[Stage {i+1}] Target: {target_hash[:10]}...")

        # 충돌하는 입력값 찾기
        payload = find_collision(target_hash)
        
        r.recvuntil(b"Guess my password(hex) > ")
        r.sendline(payload.encode())

    # 플래그 출력
    r.interactive()

if __name__ == "__main__":
    solve()