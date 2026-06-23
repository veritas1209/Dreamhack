#!/usr/bin/env python3
# main 에서 995개 임베디드 ELF 체커를 카빙 -> 각자 XTEA 복호 -> arg8 -> 7바이트 -> flag.png 조립
# 사용: python3 solve_full.py /path/to/main flag_real.png
import sys, struct

BIN_SIZE = 379169
N        = 995
CHUNK    = 7
FLAG_LEN = 6963
MAGIC    = b'\x7fELF\x02\x01\x01\x00'
OFF_KEY  = (0x1286,0x128d,0x1294,0x129b)
OFF_EXP  = 0x13c3

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

def recover_chunk(bin_bytes):
    key=[struct.unpack_from('<I',bin_bytes,o)[0] for o in OFF_KEY]
    exp=struct.unpack_from('<Q',bin_bytes,OFF_EXP)[0]
    d0,d1=xtea_dec(exp&0xffffffff, exp>>32, key)
    a8=struct.pack('<II',d0,d1)
    return decode8to7(a8), a8

SIG_LEN=0x28  # magic..e_phoff (e_shoff 직전) — bin 크기와 무관하게 모든 체커가 동일

def find_starts(buf):
    pos=[]; s=0
    while True:
        i=buf.find(MAGIC,s)
        if i<0: break
        if buf[i+18:i+20]==b'\x3e\x00':  # e_machine x86-64
            pos.append(i)
        s=i+1
    return pos

def main():
    from collections import Counter
    path=sys.argv[1]; out=sys.argv[2] if len(sys.argv)>2 else 'flag_real.png'
    buf=open(path,'rb').read()
    print(f"[*] {path} size={len(buf)}")
    magics=find_starts(buf)
    print(f"[*] ELF(EXEC,x86-64) magic 총 개수: {len(magics)} (main 자신 포함)")
    # 가장 흔한 [0:0x28] 헤더 시그니처 = 체커. main 헤더/잡음 자동 제외
    cnt=Counter(bytes(buf[p:p+SIG_LEN]) for p in magics)
    sig,freq=cnt.most_common(1)[0]
    bins=sorted(p for p in magics if buf[p:p+SIG_LEN]==sig)
    print(f"[*] 체커 시그니처 빈도={freq}, 매칭 bin 수={len(bins)}")
    print(f"[*] 첫 bin@{hex(bins[0])}  마지막 bin@{hex(bins[-1])}")
    if len(bins)!=N:
        print(f"[!] 경고: 체커 {len(bins)}개 (기대 {N}). 순서/누락 점검 필요")
    chunks=[]; bad=[]
    for k,off in enumerate(bins):
        b=buf[off:off+0x2000]  # XTEA 필드는 0x13cb 이내라 앞부분만이면 충분
        seven,a8=recover_chunk(b)
        if seven is None:
            bad.append((k,'invalid '+a8.hex())); chunks.append(b'\x00'*7)
        else:
            chunks.append(seven)
    data=b''.join(chunks)[:FLAG_LEN]
    open(out,'wb').write(data)
    print(f"[*] wrote {out} ({len(data)} bytes)")
    print(f"[*] PNG magic: {data[:8].hex()} -> {'OK' if data[:8]==bytes([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]) else 'MISMATCH'}")
    print(f"[*] invalid/bad chunks: {len(bad)}")
    for k,why in bad[:20]: print(f"    bin_{k}: {why}")

if __name__=='__main__': main()
