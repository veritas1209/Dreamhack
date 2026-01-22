import socket
import re
import time
import sys

# ==========================================
# 설정
# ==========================================
HOST = 'host8.dreamhack.games'  # 실제 서버 주소로 변경 확인!
PORT = 23943                    # 접속 포트 확인!

def unshiftRight(x, shift):
    res = x
    for i in range(32):
        res = x ^ (res >> shift)
    return res

def unshiftLeft(x, shift, mask):
    res = x
    for i in range(32):
        res = x ^ ((res << shift) & mask)
    return res

def untemper(v):
    """Mersenne Twister의 Tempering 과정을 역연산"""
    v = unshiftRight(v, 18)
    v = unshiftLeft(v, 15, 0xefc60000)
    v = unshiftLeft(v, 7, 0x9d2c5680)
    v = unshiftRight(v, 11)
    return v

def temper(y):
    """Mersenne Twister Tempering"""
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= (y >> 18)
    return y

def recover_state_candidates(out_val):
    """출력값(31비트)에서 가능한 원래 상태값(32비트) 2개를 복원"""
    candidates = []
    # getrandbits(31)은 내부적으로 32비트 난수를 >> 1 한 것임
    # 따라서 원래 값의 LSB는 0 또는 1임
    val_shifted = out_val << 1
    for lsb in [0, 1]:
        # untemper를 통해 내부 상태값(MT) 복원 시도
        candidates.append(untemper(val_shifted | lsb))
    return candidates

def solve():
    count = 1
    while True:
        try:
            print(f"[*] Attempt {count}: Connecting to {HOST}:{PORT}...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
            
            # 데이터 수신
            data = b""
            while b"answer :" not in data:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
            
            # 숫자 파싱
            numbers = [int(x) for x in re.findall(r'\b\d+\b', data.decode())]
            
            if len(numbers) < 624:
                print("[!] Not enough numbers received. Retrying...")
                s.close()
                continue
                
            outputs = numbers[:624]
            
            # =================================================================
            # 핵심 수정: MT[0]도 추측해야 함 (고정값이 아님!)
            # 필요한 값: MT[0], MT[1], MT[397]
            # =================================================================
            
            # 1. MT[0] 후보 복구 (2개)
            cand_mt0 = recover_state_candidates(outputs[0])
            
            # 2. MT[1] 후보 복구 (2개)
            cand_mt1 = recover_state_candidates(outputs[1])
                
            # 3. MT[397] 후보 복구 (2개)
            cand_mt397 = recover_state_candidates(outputs[397])
                
            # 4. Target 예측 (총 2*2*2 = 8가지 경우의 수)
            candidates = set()
            
            for m0 in cand_mt0:
                for m1 in cand_mt1:
                    for m397 in cand_mt397:
                        # Twist 알고리즘 적용 (다음 블록의 첫 번째 난수 생성)
                        # y = (Upper bit of MT[0]) | (Lower 31 bits of MT[1])
                        y = (m0 & 0x80000000) | (m1 & 0x7fffffff)
                        
                        # next = MT[397] ^ (y >> 1) ^ (MATRIX_A if y is odd)
                        next_val = m397 ^ (y >> 1)
                        if y % 2 != 0:
                            next_val ^= 0x9908b0df
                        
                        # Tempering 후 31비트로 변환 (문제 조건)
                        final_target = temper(next_val) >> 1
                        candidates.add(final_target)
            
            # 12.5% 확률에 베팅 (8개 중 하나 전송)
            guess = list(candidates)[0]
            # print(f"    -> Generated {len(candidates)} candidates. Guessing: {guess}")
            
            s.sendall(f"{guess}\n".encode())
            
            # 결과 확인
            response = s.recv(1024).decode()
            
            if "DH{" in response:
                print("\n" + "="*50)
                print(f"[SUCCESS] Flag found on attempt {count}!")
                print("Response:", response.strip())
                print("="*50)
                break
            else:
                # print(f"    -> Wrong. (Expected one of the other 7)")
                s.close()
                count += 1
                # time.sleep(0.1) # 서버 부하 방지용 딜레이 (필요시 주석 해제)
                
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    solve()