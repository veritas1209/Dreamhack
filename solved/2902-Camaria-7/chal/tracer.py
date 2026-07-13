"""
ptrace page-fault S-box tracer for the Camaria encryptor.

trace(binary_path, input_path, max_groups=2000) -> list[(sbox_name, index)]

Mechanism: fork+PTRACE_TRACEME+exec the encryptor; advance to just after the
input read(); locate the 4 ARIA S-boxes in memory by their tagged-byte head
patterns; mprotect(PROT_NONE) the S-box pages; on each SIGSEGV read si_addr to
map (page-fault address -> S-box index); single-step over the faulting load with
the page temporarily readable+writable, then re-protect.  The ordered list of
(sbox, index) accesses is returned.

Each substitution layer is 16 consecutive accesses; SL1 layers read
SB1,SB2,SB3,SB4 repeating, SL2 layers read SB3,SB4,SB1,SB2 repeating.
"""
import ctypes, os, sys, struct

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]

TRACEME=0; CONT=7; SINGLESTEP=9; SYSCALL=24; GETREGS=12; SETREGS=13
GETSIGINFO=0x4202; SETOPTIONS=0x4200; EXITKILL=0x00100000; SYS_mprotect=10

class regs_t(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in
        ("r15","r14","r13","r12","rbp","rbx","r11","r10","r9","r8","rax","rcx",
         "rdx","rsi","rdi","orig_rax","rip","cs","eflags","rsp","ss",
         "fs_base","gs_base","ds","es","fs","gs")]

SBOX_HEADS = [('SB1',[0x63,0x7c,0x77,0x7b]), ('SB2',[0xe2,0x4e,0x54,0xfc]),
              ('SB3',[0x52,0x09,0x6a,0xd5]), ('SB4',[0x30,0x68,0x99,0x1b])]

def _pt(req, pid, addr, data):
    return libc.ptrace(req, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))

def trace(binary_path, input_path, max_groups=2000):
    pid = os.fork()
    if pid == 0:
        _pt(TRACEME, 0, 0, 0)
        os.execv(binary_path, [binary_path, input_path])
        os._exit(127)
    os.waitpid(pid, 0)
    _pt(SETOPTIONS, pid, 0, EXITKILL)
    mem = open(f'/proc/{pid}/mem', 'rb+', 0)

    def rd(a, n):
        mem.seek(a); return mem.read(n)
    def getregs():
        r = regs_t(); _pt(GETREGS, pid, 0, ctypes.addressof(r)); return r
    def setregs(r):
        _pt(SETREGS, pid, 0, ctypes.addressof(r))

    def find_sboxes():
        res = {}
        for line in open(f'/proc/{pid}/maps'):
            p = line.split()
            if 'r' not in p[1]: continue
            a, b = p[0].split('-'); a = int(a, 16); b = int(b, 16)
            if b - a > 64*1024*1024: continue
            try: d = rd(a, b - a)
            except: continue
            for name, head in SBOX_HEADS:
                pat = b''.join(struct.pack('<Q', (x << 1) | 1) for x in head)
                i = d.find(pat)
                if i >= 0: res[name] = a + i
        return res

    # advance to just after the input read() syscall
    entry = True; _pt(SYSCALL, pid, 0, 0); sb = None
    while True:
        _, st = os.waitpid(pid, 0)
        if os.WIFEXITED(st):
            raise RuntimeError('process exited before sboxes found')
        r = getregs()
        if (not entry) and r.orig_rax == 0:
            s = find_sboxes()
            if len(s) == 4: sb = s; break
        entry = not entry; _pt(SYSCALL, pid, 0, 0)

    sbase = sorted(sb.values())
    sbname = {v: k for k, v in sb.items()}
    pages_lo = min(sbase) & ~0xfff
    pages_hi = (max(sbase) + 2048 + 0xfff) & ~0xfff

    r = getregs()
    SYS_INSN = r.rip - 2
    assert rd(SYS_INSN, 2) == b'\x0f\x05'

    def inject(nr, a1, a2, a3):
        sv = getregs()
        rr = regs_t(); ctypes.memmove(ctypes.addressof(rr), ctypes.addressof(sv), ctypes.sizeof(rr))
        rr.rax = nr; rr.rdi = a1; rr.rsi = a2; rr.rdx = a3; rr.rip = SYS_INSN
        setregs(rr)
        _pt(SINGLESTEP, pid, 0, 0); os.waitpid(pid, 0)
        setregs(sv)

    def protect(p):
        inject(SYS_mprotect, pages_lo, pages_hi - pages_lo, p)

    def sbox_of(addr):
        for base in sbase:
            if base <= addr < base + 2048:
                return sbname[base], (addr - base) // 8
        return None, None

    protect(0)  # PROT_NONE
    accesses = []
    _pt(CONT, pid, 0, 0)
    cap = max_groups * 16
    while True:
        _, st = os.waitpid(pid, 0)
        if os.WIFEXITED(st) or os.WIFSIGNALED(st):
            break
        sig = os.WSTOPSIG(st)
        if sig == 11:  # SIGSEGV
            si = (ctypes.c_char * 128)()
            _pt(GETSIGINFO, pid, 0, ctypes.addressof(si))
            addr = struct.unpack_from('<Q', bytes(si), 16)[0]
            name, idx = sbox_of(addr)
            if name is not None:
                accesses.append((name, idx))
            protect(3)                       # PROT_READ|PROT_WRITE
            _pt(SINGLESTEP, pid, 0, 0)
            _, st2 = os.waitpid(pid, 0)
            if os.WIFEXITED(st2): break
            protect(0)                       # PROT_NONE
            if len(accesses) >= cap:
                try: os.kill(pid, 9)
                except: pass
                break
            _pt(CONT, pid, 0, 0)
        else:
            _pt(CONT, pid, 0, sig)           # forward other signals
    try:
        mem.close()
    except: pass
    try:
        os.kill(pid, 9); os.waitpid(pid, 0)
    except: pass
    return accesses

if __name__ == '__main__':
    acc = trace(sys.argv[1], sys.argv[2])
    print('accesses', len(acc))
