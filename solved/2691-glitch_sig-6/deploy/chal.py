import socket
import math
import itertools
import time
from Crypto.Util.number import isPrime, inverse

def solve():
    HOST = 'localhost'
    PORT = 5000
    
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
                break

        # 서명 파싱
        for line in buffer.splitlines():
            if "faulty_sig =" in line:
                val = int(line.split("=")[1].strip())
                sigs.append(val)
                
        if len(sigs) < 20:
            s.close()
            continue
            
        u = list(set(sigs))
        print(f"[*] 중복 제거 후 고유한 오류 서명 개수: {len(u)}")
        
        # 1. q 찾기
        q = math.gcd(u[0] - u[1], u[0] - u[2])
        for i in range(3, len(u)):
            q = math.gcd(q, u[0] - u[i])
            
        if q.bit_length() != 256 or not isPrime(q):
            print(f"[-] 유효하지 않은 q 값입니다. 재시도합니다.")
            s.close()
            continue
        print(f"[+] 완벽한 소수 q를 복구했습니다! (256 bits)")

        # ==============================================================
        # 2. p 찾기 (수학적 최적화 핵심 구간)
        # ==============================================================
        print("[*] STEP 2: p 값 복구 시도 중... (Grouping 가속 알고리즘 적용)")
        start_time = time.time()
        
        # 가장 무거운 연산인 큰 수 거듭제곱 미리 캐싱 (Precomputation)
        u2 = [pow(x, 2) for x in u]
        pairs = [(A, B) for A in range(len(u)) for B in range(len(u)) if A != B]
        
        p = None
        correct_pair = None
        found = False
        
        # 기준 쌍(P1)을 고정하고 수학적으로 유의미한 그룹 내에서만 GCD 탐색
        for P1 in pairs:
            W_list = []
            
            for P2 in pairs:
                if P1 == P2: continue
                # 자명한 식(같은 서명들끼리의 교차) 배제
                if len(set([P1[0], P1[1], P2[0], P2[1]])) < 3: continue
                
                # 큰 수 곱셈은 캐싱된 u2 리스트 활용
                V = abs(u2[P1[0]] * u[P2[1]] - u2[P2[0]] * u[P1[1]])
                if V > 0 and V % q == 0:
                    W_list.append(V // q)
            
            # W_list 그룹 내부에서 쌍 단위 GCD 탐색
            for i in range(len(W_list)):
                for j in range(i + 1, len(W_list)):
                    g = math.gcd(W_list[i], W_list[j])
                    if g.bit_length() == 256 and isPrime(g):
                        p = g
                        correct_pair = P1
                        found = True
                        break
                if found: break
            if found: break
            
        calc_time = time.time() - start_time
        print(f"[*] 연산 소요 시간: {calc_time:.4f} 초")
        
        if not p:
            print("[-] 현재 서명 조합 내에 완벽한 쌍이 없습니다. (확률적 정상 동작)\n[-] 서버에 재연결하여 새로운 서명을 받아옵니다...\n")
            s.close()
            time.sleep(0.5)
            continue
            
        print(f"[+] 완벽한 소수 p를 찾았습니다! ({p.bit_length()} bits)")
        
        # 3. m 복구 (CRT)
        print("[*] STEP 3: 원본 메시지(m) 복구 및 플래그 획득 중...")
        A, B = correct_pair
        e = 65537
        N = p * q
        
        try:
            # u[B]의 역원을 구할 때 p가 확실한 소수이므로 역원 계산이 보장됨
            sp_cand = (u2[A] * inverse(u[B], p)) % p
            mp = pow(sp_cand, e, p)
            mq = pow(u[0], e, q)
            
            q_inv = inverse(q, p)
            p_inv = inverse(p, q)
            
            m = (mp * q * q_inv + mq * p * p_inv) % N
        except Exception as err:
            print(f"[-] 연산 중 예상치 못한 오류 발생: {err}")
            s.close()
            continue
            
        print(f"[+] 복구된 원본 메시지(m): {m}")
        
        # 4. 서버에 메시지 전송
        print("[*] 서버에 메시지를 전송하고 플래그를 요청합니다...")
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