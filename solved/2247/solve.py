import socket
from math import gcd

def egcd(a, b):
    if b == 0: return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

def inv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1: raise ValueError
    return x % m

def solve():
    # 서버 연결
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)  # 타임아웃 설정
    s.connect(('host1.dreamhack.games', 12656))
    
    # 초기 데이터 수신 (더 많이 기다림)
    data = b""
    while b">" not in data:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk
    
    data = data.decode()
    print("Received data:")
    print(data)
    print("-" * 50)
    
    lines = data.strip().split('\n')
    
    # 파싱
    params = {}
    for line in lines:
        if '=' in line and not line.startswith('send'):
            key, val = line.split('=', 1)
            try:
                params[key] = int(val, 16)
            except:
                pass
    
    n = params['n']
    e = params['e']
    m_leak = params['m_leak']
    s_good = params['s_good']
    s_bad = params['s_bad']
    m_target = params['m_target']
    
    print("Factoring n...")
    # n 인수분해
    factor = gcd(abs(s_good - s_bad), n)
    
    if 1 < factor < n:
        q = factor
        p = n // q
        
        # 검증
        if p * q != n:
            p, q = q, p
            
        print(f"Found factors!")
        
        # 개인키 d 계산
        phi = (p - 1) * (q - 1)
        d = inv(e, phi)
        
        # m_target 서명
        sig = pow(m_target, d, n)
        
        # 검증
        if pow(sig, e, n) == m_target:
            print("Signature verified locally!")
        
        # 서명 전송
        sig_hex = hex(sig)[2:]
        response = f"sig={sig_hex}\n"
        print(f"Sending: sig={sig_hex[:40]}...")
        s.send(response.encode())
        
        # 플래그 수신 (더 많이 기다림)
        s.settimeout(5)
        flag_data = b""
        try:
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                flag_data += chunk
                if b"\n" in flag_data or b"DH{" in flag_data:
                    break
        except socket.timeout:
            pass
        
        flag = flag_data.decode()
        print(f"\nReceived response: {flag}")
    else:
        print(f"Failed to factor n")
        
    s.close()

if __name__ == "__main__":
    solve()