#!/usr/bin/env python3
# 패치된(=VM이 진짜 값을 써넣은) checker bin 하나에서 8바이트 청크를 복원.
# non-PIE 고정 오프셋: encrypt()의 XTEA 키 4워드, check()의 movabs 기대값.
import struct, sys
OFF_KEY = [0x1286, 0x128d, 0x1294, 0x129b]   # mov dword 즉시값
OFF_EXP = 0x13c3                              # movabs rax, <expected> 즉시값
DELTA, M = 0x9e3779b9, 0xffffffff

def xtea_decrypt(v0, v1, key, rounds=32):
    s = (DELTA*rounds) & M
    for _ in range(rounds):
        t = ((((v1<<4)&M) ^ (v1>>5)) + v1) & M
        v1 = (v1 - (t ^ ((s + key[(s>>11)&3]) & M))) & M
        s = (s - DELTA) & M
        t = ((((v0<<4)&M) ^ (v0>>5)) + v0) & M
        v0 = (v0 - (t ^ ((s + key[s&3]) & M))) & M
    return v0, v1

def recover(path):
    b = open(path,'rb').read()
    key = [struct.unpack_from('<I', b, o)[0] for o in OFF_KEY]
    exp = b[OFF_EXP:OFF_EXP+8]
    v0, v1 = struct.unpack('<II', exp)
    p0, p1 = xtea_decrypt(v0, v1, key)
    arg8 = struct.pack('<II', p0, p1)         # = argv[1] (base-255 MSB-first)
    return key, exp, arg8

def decode8to7(a8):                            # 인코딩 역변환: V=Σ(e_i-1)*255^(7-i)
    V = 0
    for e in a8: V = V*255 + (e-1)
    if V >= (1<<56): raise ValueError("overflow(=FAKE/unpatched)")
    return V.to_bytes(7,'big')

def valid(a8):
    return a8[0] in (1,2) and all(x!=0 for x in a8)

if __name__ == "__main__":
    for p in sys.argv[1:]:
        key, exp, a8 = recover(p)
        ok = valid(a8)
        line = f"{p}: key={[hex(k) for k in key]} exp={exp.hex()} arg8={a8.hex()} valid={ok}"
        try: line += " 7byte="+decode8to7(a8).hex()
        except Exception as e: line += f" ({e})"
        print(line)
