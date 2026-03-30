import math
import os
import subprocess
from pwn import *
from Crypto.Util.number import inverse

# 터미널 창 더러워지는 통신 로그 끄기
context.log_level = 'error' 

print("[*] Compiling C++ solver with OpenMP...")
os.system("g++ -O3 -fopenmp solver.cpp -lgmp -o solver_bin")
print("[*] Compilation Done. Starting Auto-Farming Mode...\n")

attempts = 0
while True:
    attempts += 1
    print(f"[*] Attempt {attempts}... ", end="", flush=True)
    
    try:
        r = remote("host8.dreamhack.games", 21215)
    except:
        print("Connection Failed. Retrying...")
        continue
        
    S_list = []
    for _ in range(20):
        line = r.recvline().decode().strip()
        if "faulty_sig = " in line:
            sig_val = int(line.split(" = ")[1])
            S_list.append(sig_val)
            
    U = list(set(S_list))
    if len(U) < 4:
        r.close()
        print("Not enough unique signatures.")
        continue

    q = abs(U[0] - U[1])
    for i in range(2, min(10, len(U))):
        q = math.gcd(q, abs(U[0] - U[i]))

    # C++에 짬때리기 (여기서 1초 만에 쇼부 봄)
    proc = subprocess.Popen(['./solver_bin'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    input_data = f"{len(U)}\n" + "\n".join(map(str, U)) + f"\n{q}\n"
    out, err = proc.communicate(input_data)

    if "FAILED" in out or not out.strip():
        print("Unlucky RNG (High bits). Dropping connection.")
        r.close()
        continue # 꽝이면 서버 끊고 즉시 다시 연결!

    # 드디어 당첨!
    p = int(out.strip().split('\n')[-1])
    print(f"\n[🎉] JACKPOT on attempt {attempts}! Found p!")
    
    # 메시지 복구
    print("[+] Recovering message...")
    e = 65537
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    dp = d % (p - 1)

    m_final = None
    m_q = pow(U[0], e, q)
    q_inv = inverse(q, p)

    for i in range(len(U)):
        if m_final is not None: break
        for bit1 in range(64):
            dp_prime = dp ^ (1 << bit1)
            if math.gcd(dp_prime, p - 1) == 1:
                inv_dp = inverse(dp_prime, p - 1)
                m_p = pow(U[i], inv_dp, p)
                m_cand = m_q + q * ((m_p - m_q) * q_inv % p)

                if m_cand.bit_length() <= 500:
                    j = (i + 1) % len(U)
                    for bit2 in range(64):
                        dp_prime2 = dp ^ (1 << bit2)
                        if pow(m_cand, dp_prime2, p) == (U[j] % p):
                            m_final = m_cand
                            break

    if m_final is None:
        print("[-] Verification failed. Retrying just in case...")
        r.close()
        continue
    
    print("[+] Sending MSG to server perfectly synced...")
    
    # 1. 버퍼에 쌓여있는 '> ' 프롬프트까지만 딱 깔끔하게 읽어냄
    r.recvuntil(b"> ")
    
    # 2. 오직 정답 정수값 하나만 전송! (뒤에 잉여 데이터나 shutdown 절대 금지)
    r.sendline(str(m_final).encode())
    
    print("\n[🎉 SERVER RESPONSE 🎉]")
    try:
        # 3. 서버가 플래그를 출력하고 자연스럽게 종료(EOF)될 때까지 다 긁어옴
        flag = r.recvall(timeout=5).decode('utf-8', 'ignore')
        print(flag.strip())
    except Exception as e:
        print(f"[-] Error: {e}")
        
    break # 플래그 따면 파밍 무한 루프 종료