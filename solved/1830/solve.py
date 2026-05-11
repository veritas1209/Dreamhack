from pwn import *
import sys

context.log_level = 'debug'

def exploit():
    print("[DEBUG] === Boss-Rush CTF Exploit 시작 ===")
    p = remote('host8.dreamhack.games', 19982)
    # p = process('./main')

    # 2. 완벽하게 역산된 패스워드 페이로드
    # (Row 0: XXOOX, Row 1: OXOOX, Row 2: XXXXO, Row 3: XXXXX, Row 4: OXOOX)
    forged_password = b"XXOOX\nOXOOX\nXXXXO\nXXXXX\nOXOOX"

    print(f"[DEBUG] 계산된 최종 패스워드 페이로드:\n{forged_password.decode('utf-8')}")

    print("[DEBUG] 메인 메뉴 로딩 대기 중...")
    p.recvuntil(b"> ")
    p.sendline(b"2")

    p.recvuntil(b"Insert password pattern:\n")
    print("[DEBUG] 조작된 패스워드 전송")
    p.sendline(forged_password)

    # 3. 서버 응답 확인
    result = p.recvline().decode('utf-8')
    print(f"[DEBUG] 서버 1차 응답: {result.strip()}")

    if "Loaded from password!" in result:
        print("[DEBUG] [SUCCESS] 치트 감지 우회 성공! 1~8번 보스 처치 처리 완료.")
        print("[DEBUG] 최종 보스전(9FinalBoss) 진입 및 자동 사냥 시작...")

        # 4. 최종 보스전 자동화 루프
        while True:
            try:
                combat_log = p.recvuntil(b"> ")
                print(f"\n[DEBUG] --- 전투 상태 ---\n{combat_log.decode('utf-8').strip()}")

                # 최종 보스의 섀도우 워드 패턴 방어
                if b"casted shadow word!" in combat_log:
                    print("[DEBUG] 보스 즉사기 발동! 2번(Use potion)을 전송하여 회복합니다.")
                    p.sendline(b"2")
                else:
                    print("[DEBUG] 1번(Attack boss)을 전송하여 딜을 넣습니다.")
                    p.sendline(b"1")

                # 플래그 출력 조건
                if b"You have conquered the dungeon!" in combat_log:
                    print("[DEBUG] [CLEAR] 최종 보스 처치 완료!")
                    break

            except EOFError:
                break

        # 5. 플래그(Flag) 출력
        print("\n[★★★ FLAG 덤프 출력 ★★★]")
        final_output = p.recvall(timeout=2).decode('utf-8').strip()
        print(final_output)

    else:
        print("[DEBUG] [FAIL] 패스워드 로드 실패.")

    print("\n[DEBUG] === 스크립트 실행 종료 ===")

if __name__ == "__main__":
    exploit()