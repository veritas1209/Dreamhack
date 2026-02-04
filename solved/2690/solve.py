from pwn import *
from Crypto.Util.number import long_to_bytes

# 서버 접속 정보
HOST = 'host3.dreamhack.games'
PORT = 15718

# 오라클 매핑
oracle_map = {
    "Null": 0,
    "Eins": 1,
    "Zwei": 2,
    "Drei": 3
}

def solve():
    # p = remote(HOST, PORT) # 로컬 테스트 시 process 등 사용
    p = remote(HOST, PORT)

    # 1. N과 암호화된 m(ciphertext) 파싱
    try:
        raw_n = p.recvline().strip()
        N = int(raw_n)
        raw_c = p.recvline().strip()
        C = int(raw_c)
    except ValueError:
        print("[-] 데이터 파싱 실패. 서버 출력을 확인하세요.")
        return

    print(f"[+] N bit length: {N.bit_length()}")
    print(f"[+] Target Ciphertext: {C}")

    e = 65537
    
    # 2. 값 복구 루프
    # N이 1024비트이고 한 번에 2비트씩(0~3) 정보를 얻으므로
    # 1024 / 2 = 512번 반복하면 모든 비트를 복구할 수 있습니다.
    # 여유 있게 몇 번 더 돕니다.
    
    iters = 515
    recovered_digits = []

    # 진행 상황바
    prog = log.progress("Recovering m")

    for i in range(iters):
        # payload = C * (4^i)^e mod N
        # 즉, 평문을 4^i 배 해서 보냄
        multiplier = pow(4, i, N)
        payload = (C * pow(multiplier, e, N)) % N
        
        p.sendlineafter(b'> ', str(payload).encode())
        
        # 결과 받기
        response = p.recvline().strip().decode()
        
        # 정답을 맞춰버린 경우 (매우 드물지만 마지막에 발생 가능)
        if "Interesting" in response:
            print("[!] Unexpectedly solved inside loop?")
            break
            
        digit = oracle_map[response]
        recovered_digits.append(digit)
        
        if i % 50 == 0:
            prog.status(f"Step {i}/{iters}")

    prog.success("Digits recovered")

    # 3. 4진수 digits를 이용해 m 계산
    # m = N * ( 0.d1 d2 d3 ... (base 4) )
    # m = (Sum(digits[i] * 4^(iters-1-i)) * N) // 4^iters
    
    numerator = 0
    for d in recovered_digits:
        numerator = numerator * 4 + d
    
    # 분모는 4^iters
    denominator = pow(4, len(recovered_digits))
    
    # m 계산
    m_recovered = (numerator * N) // denominator

    print(f"[+] Recovered m (candidate): {m_recovered}")

    # 4. 정답 전송 및 플래그 획득 (오차 범위 고려 m, m+1 시도)
    for diff in range(2):
        guess = m_recovered + diff
        print(f"[*] Trying guess: {guess}")
        
        # 이미 루프가 끝나고 프롬프트(> )가 떠 있는 상태일 것입니다.
        # sendlineafter 대신 그냥 sendline을 쓰거나, 
        # 확실하게 하기 위해 clean() 후 보냅니다.
        # p.clean() # 버퍼 비우기 (필요시)
        
        p.sendline(str(guess).encode())
        
        # 반응 확인 (한 줄 읽기)
        try:
            # 정답이면 "Interesting..." 출력
            # 오답이면 "Null", "Eins" 등 출력
            response = p.recvline().decode().strip()
            print(f"[*] Server response: {response}")
            
            if "Interesting" in response:
                print("[!] Success! Switching to interactive mode for Flag...")
                # 플래그가 이어서 출력되므로 interactive로 확인
                p.interactive()
                break
        except EOFError:
            print("[-] Server closed connection.")
            break

    p.close()

if __name__ == '__main__':
    solve()