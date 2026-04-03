import math
import os
import time
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
    print("\n" + "="*50)
    print(f"[*] Attempt {attempts} - 서버 연결 및 데이터 수집 중...")
    
    try:
        r = remote("127.0.0.1", 5000)
    except:
        print("  -> [!] Connection Failed. Retrying...")
        continue
        
    S_list = []
    for i in range(20):
        line = r.recvline().decode().strip()
        if "faulty_sig = " in line:
            sig_val = int(line.split(" = ")[1])
            S_list.append(sig_val)
            
    U = list(set(S_list))
    print(f"  -> [DEBUG] 수집된 고유 서명 개수: {len(U)}개")
    if len(U) < 4:
        r.close()
        print("  -> [!] Not enough unique signatures. Retrying...")
        continue

    # q 계산 및 불순물(작은 소인수) 제거
    q = abs(U[0] - U[1])
    for i in range(2, min(10, len(U))):
        q = math.gcd(q, abs(U[0] - U[i]))

    for small_p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
        while q % small_p == 0:
            q //= small_p
            
    print(f"  -> [DEBUG] 추출된 q의 비트 길이: {q.bit_length()} bits")

    # C++에 연산 위임 및 소요 시간 측정
    print("  -> [*] C++ OpenMP Solver에 연산을 위임합니다...")
    start_time = time.time()
    
    proc = subprocess.Popen(['./solver_bin'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    input_data = f"{len(U)}\n" + "\n".join(map(str, U)) + f"\n{q}\n"
    out, err = proc.communicate(input_data)
    
    elapsed = time.time() - start_time
    print(f"  -> [DEBUG] C++ 연산 소요 시간: {elapsed:.3f}초")

    if "FAILED" in out or not out.strip():
        print("  -> [-] Unlucky RNG (High bits). Dropping connection.")
        r.close()
        continue 

    # 드디어 당첨!
    p = int(out.strip().split('\n')[-1])
    print(f"\n[🎉] JACKPOT on attempt {attempts}! Found p!")
    print(f"  -> [DEBUG] 추출된 p의 비트 길이: {p.bit_length()} bits")
    
    # 메시지 복구
    print("[+] Recovering message using CRT...")
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
                            print(f"  -> [DEBUG] 유효한 메시지 발견! (Signature 인덱스: {i}, 에러 비트: {bit1})")
                            m_final = m_cand
                            break

    if m_final is None:
        print("[-] Verification failed. Retrying just in case...")
        r.close()
        continue
    
    # ---------------------------------------------------------
    # [수정된 부분] 디버깅 로그 강화 및 Interactive 모드 전환
    # ---------------------------------------------------------
    print("\n" + "="*50)
    print(f"[+] ✨ 완벽하게 검증된 최종 메시지를 찾았습니다!")
    print(f"  -> [DEBUG] m_final (int)   : {m_final}")
    print(f"  -> [DEBUG] m_final (hex)   : {hex(m_final)}")
    try:
        print(f"  -> [DEBUG] m_final (bytes) : {long_to_bytes(m_final)}")
    except:
        pass
    print("="*50)

    print("[+] Sending MSG to server perfectly synced...")
    
    try:
        prompt = r.recvuntil(b"> ", timeout=2)
        print(f"  -> [DEBUG] Server Prompt: {prompt.decode('utf-8', 'ignore').strip()}")
    except:
        print("  -> [WARN] 서버로부터 '> ' 프롬프트를 받지 못했습니다.")

    # 정수형으로 서버에 전송 (대부분의 RSA 문제는 10진수를 요구함)
    r.sendline(str(m_final).encode())
    
    print("\n[🎉 SERVER RESPONSE 🎉]")
    try:
        # 서버가 곧바로 반응할 시간을 줌
        time.sleep(1) 
        
        # recvall 대신 최대 4096 바이트를 직접 읽어옵니다 (EOF 대기 안함)
        res = r.recv(4096, timeout=3)
        if res:
            print(res.decode('utf-8', 'ignore'))
        else:
            print("[-] (응답 없음) 서버가 데이터를 반환하지 않았습니다.")
            
    except Exception as e:
        print(f"[-] Error receiving: {e}")
        
    print("\n[*] 쉘 제어권을 넘깁니다. (엔터를 한 번 더 쳐보거나 응답을 확인하세요)")
    context.log_level = 'info' # Interactive 모드를 위해 로그 레벨 원복
    r.interactive()
    break