import socket
import math
import itertools
import time
from Crypto.Util.number import isPrime, inverse

def solve():
    HOST = 'host3.dreamhack.games'
    PORT = 19317
    
    # 서버 타임아웃이 30초이므로, 연산은 25초까지만 수행하고 리트라이합니다.
    TIME_LIMIT = 25.0 
    
    attempt = 1
    while True:
        print(f"\n{'='*60}")
        print(f"[*] 시도 {attempt}: 서버({HOST}:{PORT})에 연결 중...")
        attempt += 1
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
        except Exception as e:
            print(f"[-] 서버 연결 실패: {e}")
            return

        sigs = []
        buffer = ""
        
        print("[*] 서명 데이터를 실시간으로 수신 중...")
        s.settimeout(5.0)
        while True:
            try:
                data = s.recv(4096).decode()
                if not data: break
                buffer += data
                if ">" in buffer: break
            except socket.timeout:
                print("[-] 서명 수신 중 소켓 타임아웃 발생.")
                break

        # 서명 파싱
        for line in buffer.splitlines():
            if "faulty_sig =" in line:
                val = int(line.split("=")[1].strip())
                sigs.append(val)
                
        if len(sigs) < 20:
            print(f"[-] 서명 개수가 부족합니다. (현재: {len(sigs)}개) 서버에 재연결합니다.")
            s.close()
            continue
            
        u = list(set(sigs))
        print(f"[*] 중복 제거 후 고유한 오류 서명 개수: {len(u)}")
        
        # 1. q 찾기
        print("[DEBUG] q 값 계산 시작...")
        q = math.gcd(u[0] - u[1], u[0] - u[2])
        for i in range(3, len(u)):
            q = math.gcd(q, u[0] - u[i])
            
        if q.bit_length() != 256 or not isPrime(q):
            print(f"[-] 유효하지 않은 q 값입니다 (비트 길이: {q.bit_length()}). 재시도합니다.")
            s.close()
            continue
        print(f"[+] 완벽한 소수 q를 복구했습니다! (256 bits)")

        # ==============================================================
        # 2. p 찾기 (수학적 최적화 핵심 구간 + 타임아웃 방어)
        # ==============================================================
        print(f"[*] STEP 2: p 값 복구 시도 중... (제한 시간: {TIME_LIMIT}초)")
        start_time = time.time()
        
        # 큰 수 거듭제곱 미리 캐싱
        print("[DEBUG] 큰 수 거듭제곱(u^2) 사전 계산 중...")
        u2 = [pow(x, 2) for x in u]
        pairs = [(A, B) for A in range(len(u)) for B in range(len(u)) if A != B]
        print(f"[DEBUG] 탐색할 서명 쌍(Pairs)의 총 개수: {len(pairs)}개")
        
        p = None
        correct_pair = None
        found = False
        is_timeout = False
        
        for idx, P1 in enumerate(pairs):
            # 💡 [핵심] 25초가 넘어가면 쿨하게 포기하고 break
            elapsed_time = time.time() - start_time
            if elapsed_time > TIME_LIMIT:
                print(f"[-] ⏳ 연산 제한 시간 초과! ({elapsed_time:.2f}초 > {TIME_LIMIT}초)")
                print("[-] 서버 연결이 끊어지기 전에 능동적으로 중단하고 새 연결을 시도합니다.")
                is_timeout = True
                break
                
            # 디버깅: 진행 상황 출력 (너무 많이 출력하면 I/O 병목이 생기므로 50단위로 출력)
            if idx % 50 == 0:
                print(f"    [DEBUG] P1 탐색 진행률: {idx}/{len(pairs)} ... (경과 시간: {elapsed_time:.2f}초)")

            W_list = []
            for P2 in pairs:
                if P1 == P2: continue
                if len(set([P1[0], P1[1], P2[0], P2[1]])) < 3: continue
                
                V = abs(u2[P1[0]] * u[P2[1]] - u2[P2[0]] * u[P1[1]])
                if V > 0 and V % q == 0:
                    W_list.append(V // q)
            
            for i in range(len(W_list)):
                for j in range(i + 1, len(W_list)):
                    g = math.gcd(W_list[i], W_list[j])
                    if g.bit_length() == 256 and isPrime(g):
                        p = g
                        correct_pair = P1
                        found = True
                        print(f"    [DEBUG] 일치하는 소수 g 발견! (비트 길이: 256)")
                        break
                if found: break
            if found: break
            
        if is_timeout:
            s.close()
            continue

        calc_time = time.time() - start_time
        print(f"[*] 연산 소요 시간: {calc_time:.4f} 초")
        
        if not p:
            print("[-] 현재 서명 조합 내에 완벽한 쌍이 없습니다. (운이 없는 케이스)")
            print("[-] 서버에 재연결하여 새로운 서명을 받아옵니다...\n")
            s.close()
            time.sleep(0.5)
            continue
            
        print(f"[+] ✨ 완벽한 소수 p를 찾았습니다! ({p.bit_length()} bits)")
        
        # 3. m 복구 (CRT)
        print("[*] STEP 3: 원본 메시지(m) 복구 및 플래그 획득 중...")
        A, B = correct_pair
        e = 65537
        N = p * q
        print(f"[DEBUG] A={A}, B={B}, N 값 크기: {N.bit_length()} bits")
        
        try:
            sp_cand = (u2[A] * inverse(u[B], p)) % p
            mp = pow(sp_cand, e, p)
            mq = pow(u[0], e, q)
            
            q_inv = inverse(q, p)
            p_inv = inverse(p, q)
            
            m = (mp * q * q_inv + mq * p * p_inv) % N
            print(f"[DEBUG] CRT 복구 완료. 메시지 비트 길이: {m.bit_length()} bits")
        except Exception as err:
            print(f"[-] 연산 중 예상치 못한 오류 발생: {err}")
            s.close()
            continue
            
        print(f"[+] 복구된 원본 메시지(m): {m}")
        
        # 4. 서버에 메시지 전송
        print(f"[DEBUG] 서버에 메시지 전송 중...")
        s.sendall((str(m) + "\n").encode())
        
        res = ""
        try:
            s.settimeout(3.0)
            while True:
                data = s.recv(4096).decode()
                if not data: break
                res += data
        except socket.timeout:
            pass
            
        print("\n" + "="*60)
        print("[🎉] 서버 최종 응답:")
        for line in res.splitlines():
            if "Flag" in line or "DH{" in line:
                print(f"    >>> {line.strip()}")
        print("="*60)
        
        s.close()
        break

if __name__ == '__main__':
    solve()