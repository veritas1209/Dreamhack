import requests
import time
from randcrack import RandCrack

# ==========================================
# 설정 (실제 서버 URL로 변경하세요)
# ==========================================
TARGET_URL = "http://host8.dreamhack.games:22653" 

sess = requests.Session()

def make_bet(guess_val):
    """베팅 요청을 보내고 결과를 반환"""
    try:
        res = sess.post(f"{TARGET_URL}/api/bet", json={"guess": guess_val})
        return res.json()
    except Exception as e:
        print(f"[!] Network Error: {e}")
        return None

def buy_flag():
    """플래그 구매 요청"""
    res = sess.post(f"{TARGET_URL}/api/buy_flag")
    return res.json()

def solve():
    print("[*] Exploit started...")
    
    # 세션 초기화를 위해 메인 페이지 접속 (쿠키 획득)
    sess.get(TARGET_URL)

    rc = RandCrack()
    
    # ---------------------------------------------------------
    # 단계 1: 624개의 샘플 수집 (상태 복구)
    # ---------------------------------------------------------
    print("[*] Collecting 624 samples to sync RNG state...")
    
    last_bet_no = 0

    for i in range(624):
        # 0을 베팅하여 데이터 수집
        data = make_bet(0)
        
        if not data or not data.get('ok'):
            print(f"[!] Error collecting sample {i}: {data}")
            return

        server_roll = data['roll']
        bet_no = data['bet_no']
        
        # 역산: raw = roll ^ bet_no
        raw_rand_bits = server_roll ^ bet_no
        
        # 크래커에 제출
        rc.submit(raw_rand_bits)
        last_bet_no = bet_no
        
        if i % 100 == 0:
            print(f"    Collected {i}/624 samples... (Current BetNo: {bet_no})")

    print(f"[+] RNG state synchronized! Last BetNo was {last_bet_no}.")

    # ---------------------------------------------------------
    # 단계 2: 예측 및 포인트 획득
    # ---------------------------------------------------------
    wins_needed = 100
    print(f"[*] Attempting to win {wins_needed} times...")

    for i in range(wins_needed):
        # 1. 다음 난수(raw) 예측
        predicted_raw = rc.predict_getrandbits(32)
        
        # 2. 다음 베팅 번호 예측 (마지막 번호 + 1)
        # 내가 보내는 요청이 서버에서 처리될 때의 번호여야 함
        predicted_bet_no = last_bet_no + 1
        
        # 3. 정답 계산: roll = (raw ^ bet_no) & 0xFFFFFFFF
        predicted_roll = (predicted_raw ^ predicted_bet_no) & 0xFFFFFFFF
        
        # 4. 베팅 전송
        res = make_bet(predicted_roll)
        
        if not res:
            break
            
        # 결과 확인 및 디버깅
        server_actual_roll = res['roll']
        server_actual_bet_no = res['bet_no']
        server_actual_raw = server_actual_roll ^ server_actual_bet_no # 검증용 역산

        if res.get('win'):
            print(f"    [Win {i+1}/{wins_needed}] Points: {res['points']:,}")
            last_bet_no = server_actual_bet_no # 동기화 유지
        else:
            print(f"\n[!!!] PREDICTION FAILED at step {i} [!!!]")
            print(f"    Target Guess (My Calc): {predicted_roll}")
            print(f"    Actual Roll  (Server):  {server_actual_roll}")
            print("-" * 40)
            print(f"    Predicted Raw: {predicted_raw}")
            print(f"    Actual Raw:    {server_actual_raw}")
            print(f"    Diff:          {predicted_raw - server_actual_raw}")
            print("-" * 40)
            print(f"    Predicted BetNo: {predicted_bet_no}")
            print(f"    Actual BetNo:    {server_actual_bet_no}")
            
            if predicted_raw != server_actual_raw:
                print("    -> CONCLUSION: RNG State mismatch. randcrack failed to sync.")
            elif predicted_bet_no != server_actual_bet_no:
                print("    -> CONCLUSION: BetNo mismatch. Request order issue.")
            else:
                print("    -> CONCLUSION: Unknown logic error.")
            return

    # ---------------------------------------------------------
    # 단계 3: 플래그 구매
    # ---------------------------------------------------------
    print("[*] Buying the flag...")
    flag_res = buy_flag()
    
    if flag_res.get('ok'):
        print(f"\n[SUCCESS] FLAG: {flag_res['flag']}")
    else:
        print(f"\n[ERROR] Could not buy flag: {flag_res}")

if __name__ == "__main__":
    solve()