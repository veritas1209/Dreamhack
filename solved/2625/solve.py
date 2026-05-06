from pwn import *

def solve_quadratic_residue():
    # 서버 주소 (환경에 맞게 수정해주세요)
    host = 'host3.dreamhack.games'
    port = 23322
    
    print(f"[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] {host}:{port} 서버에 접속합니다...")
    p_conn = remote(host, port)
    
    # 1. 소수 p 획득
    p_conn.recvuntil(b"p = ")
    p = int(p_conn.recvline().strip())
    print(f"[DEBUG] 소수 p 획득 완료: {str(p)[:30]}... (생략)")
    
    token = 0
    
    # 2. 64개의 k 값을 읽고 각각 이차 잉여 여부 판단
    print("\n[DEBUG] 64비트 토큰 복원 시작...")
    for i in range(64):
        # k 값 수신
        k_str = p_conn.recvline().strip()
        k = int(k_str)
        
        # 오일러 판정법 (Euler's Criterion) 적용
        # k^((p-1)/2) mod p 계산
        legendre = pow(k, (p - 1) // 2, p)
        
        if legendre == 1:
            bit = 0
        elif legendre == p - 1:
            bit = 1
        else:
            print(f"[ERROR] 예상치 못한 결과 발생: {legendre}")
            return
            
        # 알아낸 비트를 토큰의 i번째 자리에 삽입
        token |= (bit << i)
        
    print(f"\n[DEBUG] 64비트 토큰 완벽 복원 완료!")
    print(f"[DEBUG] 복원된 토큰 값: {token}")
    
    # 3. 토큰 전송 및 플래그 획득
    p_conn.sendlineafter(b"> ", str(token).encode())
    
    flag = p_conn.recvline().strip().decode('utf-8')
    
    print(f"\n[DEBUG] ================= 최종 결과 =================")
    print(f"[FLAG] {flag}")
    
    p_conn.close()

if __name__ == "__main__":
    solve_quadratic_residue()