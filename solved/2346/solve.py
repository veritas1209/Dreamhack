from pwn import *

# 디버깅이 편하도록 모든 입출력 패킷과 로그를 화면에 출력합니다.
context.log_level = 'debug'

def main():
    # log.info("로컬 서버(127.0.0.1:5000)에 연결을 시도합니다...")
    p = remote('host3.dreamhack.games', 17431)

    # 1. Order 전송
    order_val = "115792089237316195423570985008687907853406176591398860056200711012391761790358"
    log.info(f"계산된 Order 값을 전송합니다: {order_val}")
    p.sendlineafter(b"Order? > ", order_val.encode())

    # 2. 나눗셈을 8회로 단축한 최종 최적화 페이로드
    # 이전 코드의 논리 오류(x1 분모 곱셈 에러)를 수정하고 공통 분모로 묶었습니다.
    payload_lines = [
        "v=v+y",
        "v0=v/v",  # MyField(1) 생성
        "u1=u*u*u+u*u*x+u*x*x+x*x*x+u*u+u*x+x*x+u+x+v0", # 분자 그룹화
        "v=u1/v-x-u",
        "y=y-x*x-v*x",
        "u=x+u",
        "x=v+v-1",
        "x0=x/x",  # MyField(1) 생성
        "x1=x0-y*2-v*v", # 분자 그룹화
        "x=x1/x-u",
        "y=x*x+v*x+y",
        "v=y-x*x-x/2",
        "u=v+v-v0*3/4",
        "y=v0-v",
        "y=y/u-x",
        "u=y*y+y/2+v",
        "x=y",
        "y=u"
    ]
    
    payload = "\n".join(payload_lines)

    log.info("최적화된 페이로드 전송 준비 완료. 서버의 입력을 대기합니다...")
    p.recvuntil(b"Give me code!\n")
    
    log.info("페이로드 전송 중...")
    p.sendline(payload.encode())
    
    # 입력을 종료하기 위해 빈 줄(Enter)을 한 번 더 전송합니다.
    p.sendline(b"")
    log.success("페이로드 및 종료 신호 전송 완료! 연산이 끝날 때까지 대기합니다.")

    # 3. 결과 확인 (interactive 모드로 전환하여 플래그 출력 확인)
    # 디버그 모드가 켜져 있으므로 Passed step... 문구가 실시간으로 출력됩니다.
    p.interactive()

if __name__ == "__main__":
    main()