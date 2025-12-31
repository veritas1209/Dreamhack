#!/usr/bin/env python3
from pwn import *
import re

# 연결 설정
HOST = 'host8.dreamhack.games'
PORT = 18496

def solve():
    # 서버에 연결
    conn = remote(HOST, PORT)
    
    print("[*] Connected to server")
    print("[*] Solving 50 addition problems...")
    
    # 50개의 문제 풀기
    for i in range(50):
        # 문제 수신: "1234+5678=?"
        question = conn.recvline().decode().strip()
        print(f"[{i+1}/50] Question: {question}")
        
        # 정규표현식으로 숫자 추출
        match = re.match(r'(\d+)\+(\d+)=\?', question)
        if match:
            num1 = int(match.group(1))
            num2 = int(match.group(2))
            answer = num1 + num2
            
            print(f"[{i+1}/50] Answer: {answer}")
            
            # 답 전송
            conn.sendline(str(answer).encode())
        else:
            print(f"[-] Failed to parse question: {question}")
            conn.close()
            return False
    
    # 결과 수신
    result = conn.recvline().decode().strip()
    print(f"\n[+] {result}")
    
    if "Nice" in result:
        flag = conn.recvline().decode().strip()
        print(f"[+] Flag: {flag}")
        conn.close()
        return True
    else:
        print(f"[-] Unexpected response: {result}")
        conn.close()
        return False

if __name__ == '__main__':
    try:
        solve()
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()