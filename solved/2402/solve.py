from pwn import *
from Crypto.Util.number import inverse

# 로그 레벨 설정 (불필요한 디버그 메시지 숨김)
context.log_level = 'error' 

def solve():
    attempt_count = 0
    
    while True: # 전체 재접속 루프 (10초 타임아웃 대응)
        r = None
        attempt_count += 1
        print(f"\n[+] Try Connection #{attempt_count}")
        
        try:
            # 1. 서버 연결
            # r = process(['python3', 'prob.py']) # 로컬 테스트 시
            r = remote('host8.dreamhack.games', 16962) 
            
            # 2. 정보 획득 (메뉴 1)
            r.sendlineafter(b'> ', b'1')
            r.recvuntil(b'n = ')
            n = int(r.recvline().strip())
            r.recvuntil(b'g = ')
            g = int(r.recvline().strip())
            r.recvuntil(b'c1 = ')
            c1 = int(r.recvline().strip())

            print(" [*] Got n, g, c1. Start spamming menu 2...")

            # 3. Oracle 공격 (메뉴 2 광클)
            c2 = 0
            found = False
            try_cnt = 0
            
            # 연결이 살아있는 동안 무한 반복
            while True:
                try:
                    r.sendline(b'2') # sendlineafter가 아니라 sendline으로 속도 향상
                    
                    # 결과 파싱 (c2와 프롬프트까지 한 번에 읽기)
                    # 타임아웃을 짧게 주어 반응 없으면 바로 재접속 로직으로 넘김
                    ret = r.recvuntil(b'> ')
                    
                    try_cnt += 1
                    print(f"\r [~] Spamming menu 2... count: {try_cnt}", end='')
                    
                    # c2 값 추출 (마지막 c2 = ... 부분 파싱)
                    if b'c2 =' in ret:
                        lines = ret.split(b'\n')
                        for line in lines:
                            if b'c2 =' in line:
                                c2 = int(line.split(b'=')[1].strip())

                    # Oracle 확인
                    if b"Hmm..?" in ret:
                        print(f"\n [!] Collision found at count {try_cnt}!")
                        found = True
                        break
                        
                except EOFError:
                    # 2번 누르다가 10초 지나서 끊긴 경우 -> 루프 탈출 후 재접속
                    break
                except Exception:
                    break

            if not found:
                print("\n [-] Timeout. Retrying connection...")
                try: r.close()
                except: pass
                continue

            # 4. 충돌 발견 시 계산 및 정답 제출
            print(" [*] Solving Discrete Logarithm...")
            target = (c2 * inverse(c1, n)) % n
            limit = 1 << 28
            
            # BSGS 알고리즘
            m = int(limit**0.5) + 1
            table = {}
            curr = 1
            for j in range(m):
                table[curr] = j
                curr = (curr * g) % n
            
            factor = inverse(pow(g, m, n), n)
            curr = target
            diff = None
            
            for i in range(m):
                if curr in table:
                    diff = i * m + table[curr]
                    break
                curr = (curr * factor) % n
            
            if diff:
                print(f" [+] Found answer: {diff}")
                
                # 이미 위에서 '> ' 까지 읽었으므로 바로 전송
                r.sendline(b'3')
                # 혹시 모르니 프롬프트 정리
                # r.recvuntil(b'answer? > ') 
                # 위 recvuntil이 꼬일 수 있으니 그냥 sendline으로 밀어넣기
                r.sendline(str(diff).encode())
                
                print(" [*] Sending answer...")
                
                # 결과 확인 (Flag 읽기)
                res = r.recvall(timeout=3).decode(errors='ignore')
                if "DH{" in res:
                    print("\n" + "#"*50)
                    print(res)
                    print("#"*50 + "\n")
                    r.close()
                    return # 완전 종료
                else:
                    print(" [?] Flag not found in response.")
            
            r.close()

        except KeyboardInterrupt:
            print("\n [*] User interrupted.")
            return
        except Exception as e:
            print(f"\n [!] Error: {e}")
            try: r.close()
            except: pass

if __name__ == "__main__":
    solve()