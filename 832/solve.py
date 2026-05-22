from pwn import *

# 서버 접속
p = remote('host8.dreamhack.games', 10933)

# 정답 경로
payload = "wwwwwwwwwwwwwwawwwwwwwwwwwwwwawwwwwwwwwwwwwwawwwwwwwwwwwwwwawwwwwwwwwwwwwwawwwwwwwwwwwwwwawwwwwwwwwwwwwwawwwwwwwwwwwwwwwa"

p.recvuntil(b"Welcome to maze!\n")
print(f"[*] 총 {len(payload)}번의 이동을 시작합니다...")

# 마지막 입력 전까지만 반복
for i in range(len(payload) - 1):
    p.recvuntil(b"Input (w/a/s/d) > ")
    p.send(payload[i].encode() + b"\n")

# 마지막 입력 전송
p.recvuntil(b"Input (w/a/s/d) > ")
p.send(payload[-1].encode() + b"\n")

# [핵심] 이제 프롬프트를 찾지 말고 서버가 뱉어내는 플래그를 멍하니 기다립니다.
print("\n[*] 플래그 수신 중...")
try:
    # 서버가 exit(0)로 종료되기 전까지 쏟아내는 모든 데이터를 읽습니다.
    flag = p.recvall(timeout=3).decode(errors='ignore')
    print(f"\n[+] 서버 응답 결과:\n{flag}")
except Exception as e:
    print(f"[-] 플래그 수신 중 에러: {e}")

p.close()