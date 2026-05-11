from pwn import *

# ==========================================
# 드림핵 인스턴스 접속 정보 설정 (발급받은 주소로 변경하세요)
# ==========================================
HOST = "host8.dreamhack.games"  # 예: "host3.dreamhack.games"
PORT = 12846                    # 예: 12345

def main():
    print(f"[*] {HOST}:{PORT} 에 접속을 시도합니다...")
    p = remote(HOST, PORT)

    # 앞서 역연산으로 구한 정답 문자열
    payload = b"C0ngr47ulati0ns, y0u'v3 s0m3how 4n4ly23d Pyth0n byt3c0d3!"

    # 'input? ' 프롬프트가 출력될 때까지 대기
    print("[*] 서버 프롬프트를 기다리는 중...")
    p.recvuntil(b"input? ")
    
    # 페이로드 전송 (sendline은 자동으로 끝에 개행문자 \n을 붙여줍니다)
    print(f"[*] 페이로드 전송: {payload.decode()}")
    p.sendline(payload)

    # 서버의 응답(진짜 플래그) 출력 후 터미널 상호작용 모드 진입
    print("[*] 결과 확인:")
    p.interactive()

if __name__ == "__main__":
    main()