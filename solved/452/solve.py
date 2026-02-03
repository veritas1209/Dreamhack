from pwn import *
from tqdm import tqdm # 진행 상황 표시용 (없으면 pip install tqdm)

# 서버 연결 정보
HOST = 'host3.dreamhack.games'
PORT = 15565

# pwn 설정
context.log_level = 'error' # 로그 출력 최소화 (속도 향상)

def solve():
    # 서버 연결
    r = remote(HOST, PORT)

    # 각 인덱스별로 등장한 암호문 바이트를 저장할 집합 리스트
    # 예: seen_bytes[0]은 플래그 첫 번째 글자의 암호문으로 등장한 값들의 집합
    seen_bytes = []
    
    # 충분한 횟수만큼 반복 (약 1500~2000회 권장)
    # Coupon Collector 문제에 따라 255개의 값을 다 보려면 n*log(n) 정도 필요
    TRY_COUNT = 1800 
    
    # 임의의 키 (플래그 길이보다 커야 함. 안전하게 1000 설정)
    KEY = str(1000).encode()

    print(f"[*] Collecting samples... ({TRY_COUNT} iterations)")

    for _ in tqdm(range(TRY_COUNT)):
        # 메뉴 출력 대기 및 선택 (3. encrypt flag)
        r.recvuntil(b">> ")
        r.sendline(b"3")
        
        # 키 입력
        r.recvuntil(b"key >> ")
        r.sendline(KEY)
        
        # 결과 수신
        r.recvuntil(b"result : ")
        res_hex = r.recvline().strip().decode()
        
        # 헥스 문자열을 바이트 리스트로 변환
        # 예: "4142" -> [0x41, 0x42]
        current_cipher_bytes = [int(res_hex[i:i+2], 16) for i in range(0, len(res_hex), 2)]
        
        # 처음 실행 시 리스트 초기화
        if not seen_bytes:
            seen_bytes = [set() for _ in range(len(current_cipher_bytes))]
            
        # 각 자리별로 등장한 값 기록
        for idx, val in enumerate(current_cipher_bytes):
            seen_bytes[idx].add(val)

    # 플래그 복구
    flag = ""
    print("\n[*] Analyzing results...")
    
    for idx, s in enumerate(seen_bytes):
        # 0~255 중 등장하지 않은 값 찾기
        missing = []
        for cand in range(256):
            if cand not in s:
                missing.append(cand)
        
        if len(missing) == 1:
            # 유일하게 등장하지 않은 값이 있다면, 그게 바로 (P ^ 0xFF)
            char_code = missing[0] ^ 0xff
            flag += chr(char_code)
        else:
            # 만약 등장하지 않은 값이 여러 개라면, 시도 횟수가 부족했던 것임
            flag += "?"
            print(f"[!] Index {idx}: {len(missing)} candidates left. Need more iterations.")

    print(f"\n[+] Flag: {flag}")
    r.close()

if __name__ == "__main__":
    solve()