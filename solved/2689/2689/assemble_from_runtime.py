#!/usr/bin/env python3
# 줄: "bin_<n> keyblob=<64hex> exp=<16hex>"  -> XTEA복호 -> 디코드 -> flag_real.png
# 사용: python3 assemble_from_runtime.py runtime_xtea.txt flag_real.png [static_dir]
import sys, struct, re, os
def xtea_dec(v0,v1,key,rounds=32,delta=0x9e3779b9):
    m=0xffffffff; s=(delta*rounds)&m
    for _ in range(rounds):
        v1=(v1-(((v0<<4 ^ v0>>5)+v0) ^ (s+key[(s>>11)&3])))&m
        s=(s-delta)&m
        v0=(v0-(((v1<<4 ^ v1>>5)+v1) ^ (s+key[s&3])))&m
    return v0,v1
def decode8to7(a8):
    V=sum((a8[i]-1)*(255**(7-i)) for i in range(8))
    return None if V>=(1<<56) else V.to_bytes(7,'big')
def keys_from_blob(kb):  # kb: 32 bytes, 즉시값 at rel 0,7,14,21
    return [struct.unpack_from('<I',kb,r)[0] for r in (0,7,14,21)]
def recover(keyblobhex,exphex):
    kb=bytes.fromhex(keyblobhex); key=keys_from_blob(kb)
    exp=struct.unpack('<Q',bytes.fromhex(exphex))[0]
    d0,d1=xtea_dec(exp&0xffffffff,exp>>32,key)
    a8=struct.pack('<II',d0,d1)
    return decode8to7(a8),a8,key,exp
src=sys.argv[1]; out=sys.argv[2] if len(sys.argv)>2 else 'flag_real.png'
sdir=sys.argv[3] if len(sys.argv)>3 else None
rows={}
for ln in open(src):
    m=re.search(r'bin_(\d+)\s+keyblob=([0-9a-f]{64})\s+exp=([0-9a-f]{16})',ln)
    if m: rows[int(m.group(1))]=(m.group(2),m.group(3))
N=995; chunks=[]; bad=[]; diff=0
for k in range(N):
    if k not in rows: bad.append((k,'missing')); chunks.append(b'\x00'*7); continue
    kbh,eh=rows[k]; seven,a8,key,exp=recover(kbh,eh)
    if sdir:
        p=os.path.join(sdir,f'bin_{k}')
        if os.path.exists(p):
            b=open(p,'rb').read()
            sk=[struct.unpack_from('<I',b,o)[0] for o in (0x1286,0x128d,0x1294,0x129b)]
            se=struct.unpack_from('<Q',b,0x13c3)[0]
            if sk!=key or se!=exp: diff+=1
    if seven is None: bad.append((k,'invalid '+a8.hex())); chunks.append(b'\x00'*7)
    else: chunks.append(seven)
data=b''.join(chunks)[:6963]; open(out,'wb').write(data)
ok = data[:8]==bytes([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a])
print(f"[*] wrote {out} ({len(data)}B)  PNG magic {data[:8].hex()} -> {'OK' if ok else 'MISMATCH'}")
print(f"[*] invalid/bad: {len(bad)}", bad[:10])
if sdir: print(f"[*] runtime!=static(가짜) bin 수: {diff}  (많으면=패치 캡처 성공)")
