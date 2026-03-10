from pwn import *
import time
import sys

HOST = 'host3.dreamhack.games'
PORT = 18141

# LCG 상수
M = 1 << 48
A = 25214903917
C = 11
invA = pow(A, -1, M)
inv_1337 = pow(0x1337, -1, M)

class GenesisPRNG:
    def __init__(self, seed):
        self.M = M
        self.A = A
        self.C = C
        self.state = (seed ^ self.A) & (self.M - 1)
        
    def get_rand(self):
        self.state = (self.state * self.A + self.C) & (self.M - 1)
        return self.state >> 24 

def solve():
    context.log_level = 'info'
    log.info("Connecting to gather LCG state...")
    
    # 1. 상태 수집 (서버가 튕길 수 있으니 여기도 안전하게)
    r = None
    for _ in range(5):
        try:
            r = remote(HOST, PORT)
            r.recvuntil(b"Guest Session ID: ", timeout=5)
            tokens = r.recvline().strip().decode().split('-')
            O1 = int(tokens[0], 16)
            O2 = int(tokens[1], 16)
            r.close()
            break
        except Exception as e:
            if r: r.close()
            log.warning(f"Failed to connect, retrying... ({e})")
            time.sleep(1)
    else:
        log.error("Could not connect to the server.")
        return

    log.info("Brute-forcing lower 24 bits...")
    valid_S1s = []
    
    # 2. 가능한 모든 현재 상태(S1) 찾기 (Collision 대비)
    for x in range(1 << 24):
        guess_S1 = (O1 << 24) | x
        guess_S2 = (guess_S1 * A + C) & (M - 1)
        if (guess_S2 >> 24) == O2:
            valid_S1s.append(guess_S1)
            
    if not valid_S1s:
        log.error("Failed to find any valid LCG state")
        return
        
    log.success(f"Found {len(valid_S1s)} valid LCG state(s). Generating candidates...")
    passwords = set()
    
    # 3. 각 상태별로 역산하여 비밀번호 후보군 생성
    for S1 in valid_S1s:
        current_state = S1
        for i in range(1, 50010):
            current_state = ((current_state - C) * invA) & (M - 1)
            
            if 10000 <= i <= 50005:
                guess_lower48_seed = current_state ^ A
                lower48_K = (guess_lower48_seed ^ 0xCAFEBABE) & (M - 1)
                guess_timestamp = (lower48_K * inv_1337) & (M - 1)
                
                if 1500000000000 < guess_timestamp < 2000000000000:
                    genesis_seed = (guess_timestamp * 0x1337) ^ 0xCAFEBABE
                    prng = GenesisPRNG(genesis_seed)
                    admin_pass = f"{prng.get_rand():06x}{prng.get_rand():06x}{prng.get_rand():06x}{prng.get_rand():06x}"
                    passwords.add(admin_pass)

    passwords = list(passwords)
    log.info(f"Generated {len(passwords)} unique password candidates.")
    log.info("Starting robust server verification...")
    
    context.log_level = 'error' # 깔끔한 화면을 위해 pwntools 로그 잠시 끔
    
    # 4. 서버 검증 (재시도 로직 포함!)
    for idx, pwd in enumerate(passwords):
        sys.stdout.write(f"\r[*] Trying password {idx+1}/{len(passwords)}: {pwd}    ")
        sys.stdout.flush()
        
        while True: # 성공 또는 명확한 실패를 받을 때까지 무한 반복
            try:
                r_verify = remote(HOST, PORT)
                r_verify.recvuntil(b"> ", timeout=2)
                r_verify.sendline(b"1")
                r_verify.recvuntil(b"Enter Admin Password: ", timeout=2)
                r_verify.sendline(pwd.encode())
                
                res = r_verify.recvall(timeout=2).decode()
                r_verify.close()
                
                if "Successful" in res:
                    sys.stdout.write("\n")
                    context.log_level = 'info'
                    log.success(f"Perfect Match! Password is: {pwd}")
                    log.success("Flag Extracted Successfully:\n")
                    print(res.strip())
                    return
                elif "Failed" in res:
                    # 명확하게 비밀번호가 틀렸다는 응답을 받았으므로, 다음 비밀번호로 넘어감
                    break
                else:
                    # 서버가 튕기거나 이상한 응답을 줬을 때 0.5초 쉬고 재시도
                    time.sleep(0.5)
            except Exception:
                # 연결 거부 등 네트워크 에러가 발생하면 0.5초 쉬고 재시도
                time.sleep(0.5)

    sys.stdout.write("\n")
    context.log_level = 'info'
    log.error("Could not find the correct password among the candidates.")

if __name__ == "__main__":
    solve()