#!/usr/bin/env python3
"""
LoR - mechagolem (Lord of ROP series) solver.

The binary mmaps a fixed-address (0x34785000) region with PROT_READ|PROT_WRITE
and fills it with a giant ROP chain at boot, then stack-pivots into it.
The chain implements a Base64 encoder VM. Hidden inside it is a per-byte
check chain that, when all 46 bytes match, reaches a routine that prints
"Awesome! submit your input!" — the matching input IS the flag.

Strategy:
  1. Run the binary locally, sample the chain memory and process maps to
     recover libc base, binary base, and a full chain dump.
  2. Walk the chain symbolically starting at the first check site
     (C+0x13d0). Three check patterns are used in round-robin (mod 3):
       offset%3 == 0:  input*4 == K           (encoded = small const)
       offset%3 == 1:  input == (K>>23)&0xff  (xchg+and 0xff800000+shl 23)
       offset%3 == 2:  input == (K>>12)&0xff  (xchg+sar 6 twice+xchg)
     The walker follows succ-target pivots until it hits the Awesome
     routine, collecting 46 bytes of expected input.
  3. Open a connection (local or remote), submit option 1 + the recovered
     input, and read back "Awesome! submit your input!" as confirmation.

Usage:
    python3 solve.py                       # local /tmp/lor
    python3 solve.py HOST PORT             # remote
"""

import os
import struct
import sys
import time

from pwn import process, remote, context

context.log_level = 'error'

# ---------------------------------------------------------------------------
# Step 1: dump the chain from a freshly-spawned local process
# ---------------------------------------------------------------------------

LOR_DIR    = '/tmp/lor'              # directory with lor, libc.so.6, ld-linux*
CHAIN_BASE = 0x34785000              # mmap hint honored by the kernel; fixed
CHAIN_SIZE = 0x10000

def dump_chain():
    """Spawn lor, send '1' to reach the input prompt (chain fully populated by
    then), then snapshot chain memory and libraries' bases from /proc."""
    os.chdir(LOR_DIR)
    p = process(['./ld-linux-x86-64.so.2', './lor'],
                env={'LD_LIBRARY_PATH': '.'})
    time.sleep(0.3)
    p.recvuntil(b'> ', timeout=2)
    p.sendline(b'1')
    p.recvuntil(b'input: ', timeout=2)

    pid = p.pid
    maps = open(f'/proc/{pid}/maps').read()
    binb = libc = None
    # NB: take the FIRST (lowest-address) mapping of each library — that's the
    # actual load base. The r-xp segment lives a few pages in (~0x28000 on
    # glibc 2.35) and would give us a wrong base.
    for line in maps.splitlines():
        if line.endswith('/lor') and binb is None:
            binb = int(line.split('-')[0], 16)
        elif '/libc.so.6' in line and libc is None:
            libc = int(line.split('-')[0], 16)
    assert binb and libc, "couldn't find binary/libc bases in /proc/PID/maps"

    with open(f'/proc/{pid}/mem', 'rb', 0) as mem:
        mem.seek(CHAIN_BASE)
        chain = mem.read(CHAIN_SIZE)

    p.close()
    return chain, libc, binb


# ---------------------------------------------------------------------------
# Step 2: symbolic walker
# ---------------------------------------------------------------------------

def recover_input(chain, libc, binb):
    qw = lambda off: struct.unpack('<Q', chain[off:off+8])[0]

    # Gadget addresses (resolved against the captured libc base).
    G_POP_RAX            = libc + 0x45eb0
    G_POP_RBX            = libc + 0x35dd1
    G_ADD_RAX_RBX_POPS   = libc + 0x1348fa  # add rax,rbx; pop rbx;rbp;r12;r13;ret
    G_RAX_FROM_MEM       = libc + 0x14a39c  # mov rax,[rax]; ret
    G_POP_RSI            = libc + 0x2be51
    G_AND_EAX_ESI        = libc + 0x3a351
    G_POP_RDI            = libc + 0x2a3e5
    G_XCHG_EDI_EAX       = libc + 0x14a385
    G_SAR_RAX_6          = libc + 0x1366a0
    G_SHL_EAX_23         = libc + 0x4192c   # shl eax,0x17; or ecx,eax; ...; ret
    G_ADD_EAX_EAX        = libc + 0x1afa14  # add eax,eax; ret
    G_SUB_RAX_RDI        = libc + 0xbab68
    G_CMOVE_RAX_RDX      = libc + 0x39b1e
    G_POP_RDX_R12        = libc + 0x11f497

    INPUT_BUF   = binb + 0x1a280
    FAIL_TARGET = CHAIN_BASE + 0x5218       # = RET soft-stack pop (silent abort)

    # ---- Tiny symbolic evaluator over (operation, args...) tuples -------------
    def ev(expr, inp):
        op = expr[0]
        if op == 'INPUT': return inp & 0xffffffffffffffff
        if op == 'K':     return expr[1]
        if op == 'sar6':                                # 64-bit arithmetic shift right by 6
            v = ev(expr[1], inp)
            if v & (1 << 63): v -= 1 << 64
            return (v >> 6) & 0xffffffffffffffff
        if op == 'shl23':                               # shl eax,0x17 — affects low 32 bits, zeroes upper
            return (ev(expr[1], inp) << 23) & 0xffffffff
        if op == 'shl1':                                # add eax,eax
            return (ev(expr[1], inp) << 1) & 0xffffffff
        if op == 'and':
            return ev(expr[1], inp) & expr[2]
        raise ValueError(expr)

    def parse_check(i):
        """Parse one check site starting at chain offset `i`. Returns
        (input_offset, succ_target_offset, solved_byte) or None."""
        if qw(i) != G_POP_RAX or qw(i + 8) != INPUT_BUF:
            return None
        i += 16

        # Optional offset add: pop rbx; OFFSET; add rax,rbx; 4 dummy pops
        if qw(i) == G_POP_RBX:
            offset = qw(i + 8)
            i += 16
            if qw(i) != G_ADD_RAX_RBX_POPS: return None
            i += 8 + 32                                 # gadget + 4×8 popped operands
        else:
            offset = 0

        # rax = *rax  (load 8 bytes of input)
        if qw(i) != G_RAX_FROM_MEM: return None
        i += 8

        # mask low byte: pop rsi; 0xff; and eax,esi
        if qw(i) != G_POP_RSI or qw(i + 8) != 0xff or qw(i + 16) != G_AND_EAX_ESI:
            return None
        i += 24

        # Walk the decode block symbolically until we hit `sub rax, rdi`.
        rax = ('INPUT',)
        rdi = ('K', 0)
        rsi = ('K', 0)
        for _ in range(40):
            g = qw(i)
            if   g == G_POP_RDI:        rdi = ('K', qw(i + 8)); i += 16
            elif g == G_XCHG_EDI_EAX:   rax, rdi = rdi, rax;     i += 8
            elif g == G_SAR_RAX_6:      rax = ('sar6', rax);     i += 8
            elif g == G_SHL_EAX_23:     rax = ('shl23', rax);    i += 8
            elif g == G_ADD_EAX_EAX:    rax = ('shl1', rax);     i += 8
            elif g == G_POP_RSI:        rsi = ('K', qw(i + 8));  i += 16
            elif g == G_AND_EAX_ESI:    rax = ('and', rax, ev(rsi, 0)); i += 8
            elif g == G_SUB_RAX_RDI:    i += 8; break
            else: return None
        else:
            return None

        # Match the standard tail: pop rax FAIL; pop rdx SUCC; pop r12 0; cmove
        if qw(i) != G_POP_RAX or qw(i + 8) != FAIL_TARGET:    return None
        i += 16
        if qw(i) != G_POP_RDX_R12:                            return None
        succ = qw(i + 8)
        i += 24
        if qw(i) != G_CMOVE_RAX_RDX:                          return None

        # Brute the 256 byte values against the symbolic relation rax == rdi.
        sols = [b for b in range(256) if ev(rax, b) == ev(rdi, b)]
        if len(sols) != 1: return None
        return offset, succ - CHAIN_BASE, sols[0]

    # The check chain starts at C+0x13d0 (reached from encode_sub's tail).
    buf = bytearray(b'\x00' * 0x50)
    cur = 0x13d0
    seen = set()
    while cur not in seen:
        seen.add(cur)
        r = parse_check(cur)
        if r is None: break
        offset, succ, byte = r
        buf[offset] = byte
        cur = succ

    last = max(i for i, b in enumerate(buf) if b)
    return bytes(buf[:last + 1])


# ---------------------------------------------------------------------------
# Step 3: send the recovered input and capture the response
# ---------------------------------------------------------------------------

def submit(target, payload):
    """target=None → local; target=(host,port) → remote."""
    if target is None:
        os.chdir(LOR_DIR)
        io = process(['./ld-linux-x86-64.so.2', './lor'],
                     env={'LD_LIBRARY_PATH': '.'})
    else:
        io = remote(*target)
    io.recvuntil(b'> ')
    io.sendline(b'1')
    io.recvuntil(b'input: ')
    io.send(payload + b'\n')
    time.sleep(0.3)
    response = io.recv(timeout=2)
    io.close()
    return response


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    print('[*] dumping chain from a local instance...')
    chain, libc, binb = dump_chain()
    print(f'    libc base = {libc:#x}')
    print(f'    bin  base = {binb:#x}')
    print(f'    chain @ {CHAIN_BASE:#x}, {len(chain):#x} bytes')

    print('[*] symbolically walking 46 check sites...')
    flag = recover_input(chain, libc, binb)
    print(f'    recovered ({len(flag)} bytes): {flag!r}')

    target = None
    if len(sys.argv) == 3:
        target = (sys.argv[1], int(sys.argv[2]))
        print(f'[*] submitting to remote {target[0]}:{target[1]}...')
    else:
        print('[*] submitting locally to verify...')

    resp = submit(target, flag)
    print('[*] response:')
    print('    ' + repr(resp))

    if b'Awesome' in resp:
        print()
        print(f'[+] FLAG: {flag.decode()}')
    else:
        print('[-] chain rejected the input (something went wrong)')


if __name__ == '__main__':
    main()