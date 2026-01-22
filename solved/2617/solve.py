import socket
import re
import time

# ==========================================
# Dreamhack Server Info
# ==========================================
HOST = 'host8.dreamhack.games' 
PORT = 23943  # 포트 번호 확인하세요!

def unshiftRight(x, shift):
    res = x
    for _ in range(32):
        res = x ^ (res >> shift)
    return res & 0xFFFFFFFF

def unshiftLeft(x, shift, mask):
    res = x
    for _ in range(32):
        res = x ^ ((res << shift) & mask)
    return res & 0xFFFFFFFF

def untemper(v):
    """Mersenne Twister 역연산 (32비트 마스킹 필수)"""
    v = unshiftRight(v, 18)
    v = unshiftLeft(v, 15, 0xefc60000)
    v = unshiftLeft(v, 7, 0x9d2c5680)
    v = unshiftRight(v, 11)
    return v & 0xFFFFFFFF

def temper(y):
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= (y >> 18)
    return y & 0xFFFFFFFF

def recover_state_candidates(out_val):
    candidates = []
    # getrandbits(31)은 (output >> 1) 입니다.
    # 원래 값은 (output << 1) 이거나 (output << 1) | 1 입니다.
    val_shifted = out_val << 1
    for lsb in [0, 1]:
        candidates.append(untemper(val_shifted | lsb))
    return candidates

def solve():
    count = 1
    while True:
        s = None
        try:
            print(f"[*] Attempt {count}: Connecting to {HOST}:{PORT}...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
            
            # 데이터 수신 (모든 숫자가 다 올 때까지)
            data = b""
            while b"answer :" not in data:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
            
            numbers = [int(x) for x in re.findall(r'\b\d+\b', data.decode(errors='ignore'))]
            
            if len(numbers) < 624:
                print("[!] Not enough numbers received. Retrying...")
                s.close()
                continue
            
            outputs = numbers[:624]
            
            # 1. MT 상태 복구 후보군 생성
            cand_mt0 = recover_state_candidates(outputs[0])
            cand_mt1 = recover_state_candidates(outputs[1])
            cand_mt397 = recover_state_candidates(outputs[397])
            
            # 2. 가능한 8가지 정답 후보 생성
            candidates = set()
            for m0 in cand_mt0:
                for m1 in cand_mt1:
                    for m397 in cand_mt397:
                        # Twist Algorithm
                        y = (m0 & 0x80000000) | (m1 & 0x7fffffff)
                        next_val = m397 ^ (y >> 1)
                        if y % 2 != 0:
                            next_val ^= 0x9908b0df
                        
                        # Tempering & 31-bit truncation
                        final_target = temper(next_val) >> 1
                        candidates.add(final_target)
            
            guess = list(candidates)[0] # 하나 찍기
            print(f"[*] Sending guess: {guess}")
            
            s.sendall(f"{guess}\n".encode())
            
            # =======================================================
            # [핵심 수정] Echo(내가 보낸 값)를 무시하고 진짜 결과 읽기
            # =======================================================
            full_response = ""
            while True:
                try:
                    s.settimeout(2.0) # 2초 대기
                    chunk = s.recv(1024).decode(errors='ignore')
                    if not chunk: break
                    full_response += chunk
                    
                    if "DH{" in full_response or "nope" in full_response:
                        break
                except socket.timeout:
                    break

            print(f"[*] Server Response: {full_response.strip()}")

            if "DH{" in full_response:
                print("\n" + "="*50)
                print(f"[SUCCESS] Flag found on attempt {count}!")
                # 플래그만 깔끔하게 추출
                flag = re.search(r'DH{.*?}', full_response)
                if flag:
                    print(f"FLAG: {flag.group()}")
                print("="*50)
                break
            else:
                print("[-] Wrong guess (Echo detected or incorrect). Retrying...\n")
                s.close()
                count += 1
                
        except Exception as e:
            print(f"[!] Error: {e}")
            if s: s.close()
            time.sleep(1)

if __name__ == "__main__":
    solve()