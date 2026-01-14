import requests
import re

# 1. 문제 서버 주소 (포트 번호 확인!)
host = "http://host3.dreamhack.games:18323" # <-- 본인의 주소로 수정하세요!

# --- [Step 1 & 2] ---
# GET 요청으로 Step 1 조건 만족 -> Step 2로 리다이렉트 -> HTML 획득
url_step1 = f"{host}/step1"
params = {
    "param": "getget",
    "param2": "rerequest"
}

print("[*] Requesting Step 1 & 2...")
res = requests.get(url_step1, params=params)

# Step 2 페이지의 HTML에서 hidden value (check 값) 찾기
# HTML 예시: <input type="hidden" name="check" value="123456789">
# 정규표현식으로 value="" 안의 숫자를 추출합니다.
match = re.search(r'name=["\']check["\'].*?value=["\'](.*?)["\']', res.text)

if match:
    check_value = match.group(1)
    print(f"[+] Found Check Value: {check_value}")

    # --- [Step 3 (Flag)] ---
    # POST 요청으로 Flag 획득
    url_flag = f"{host}/flag"
    data = {
        "check": check_value,
        "param": "pooost",
        "param2": "requeeest"
    }

    print("[*] Sending POST request to /flag...")
    res_flag = requests.post(url_flag, data=data)
    
    if "DH{" in res_flag.text:
        print("\n[!!!] FLAG FOUND:")
        # 플래그만 예쁘게 잘라서 출력하거나 전체 출력
        print(res_flag.text)
    else:
        print("[-] Flag not found in response.")
        print(res_flag.text)

else:
    print("[-] Failed to find the hidden check value in Step 2 HTML.")
    print("HTML dump:", res.text)