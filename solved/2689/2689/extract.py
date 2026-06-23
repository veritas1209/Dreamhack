#!/usr/bin/env python3
# read-count 센서로 bin 의 secret 8바이트를 바이트별 복구.
# 사용: python3 extract.py <bin파일> <argv0이름> [<known_hex 검증>]
import subprocess, sys, struct
from collections import Counter

BIN=sys.argv[1]; AV0=sys.argv[2]
KNOWN=sys.argv[3] if len(sys.argv)>3 else None
CR="/host/countread"
RELA=0x1005000
# bin_0 기준 센서 인덱스 (RELASZ=0x55d28, nreloc=14647)
SENS0=[4000,5250,6600,7200,9500,11000,11500,13000]
NREL0=14647

def relasz(path):
    d=open(path,'rb').read()
    return struct.unpack_from('<Q',d,0x2f30)[0]

def countread(inp_hex, addr, want_exit=False):
    # countread <bin> <hex8> <av0> <addr> -> "0x.. reads=N exit=E"
    r=subprocess.run([CR,BIN,inp_hex,AV0,hex(addr)],capture_output=True,text=True)
    out=r.stdout.strip()
    try: reads=int(out.split('reads=')[1].split()[0])
    except: reads=-1
    if want_exit:
        try: ec=int(out.split('exit=')[1].split()[0])
        except: ec=-1
        return reads,ec
    return reads

def detect(reads):
    freq=Counter(reads.values())
    mode_val,mode_cnt=freq.most_common(1)[0]
    cands=[v for v in reads if reads[v]!=mode_val]
    if len(cands)==1: return cands[0],'outlier'
    if len(cands)==0: return None,'noresp'
    # graded: argmin
    return min(reads,key=lambda v:reads[v]),'argmin'

def main():
    nrel=relasz(BIN)//24
    scale=nrel/NREL0
    print(f"[*] {BIN} nreloc={nrel} scale={scale:.4f}")
    secret=[]
    for k in range(8):
        base_idx=round(SENS0[k]*scale)
        # 후보 인덱스: 스케일된 위치 + 약간의 윈도우 탐색
        found=None
        for off in [0,-50,50,-100,100,-200,200,-400,400]:
            idx=base_idx+off
            addr=RELA+idx*24
            reads={}
            for v in range(1,256):
                inp=bytes(secret+[v]+[0x01]*(7-k))
                reads[v]=countread(inp.hex(),addr)
            v,mode=detect(reads)
            if v is not None:
                found=(v,idx,mode); break
        if found is None:
            print(f"[!] byte{k}: 센서 응답 없음"); return
        v,idx,mode=found
        secret.append(v)
        print(f"  byte{k}: {v:#04x} (sensor idx={idx} {mode})")
    hexs=bytes(secret).hex()
    print(f"[=] secret = {hexs}")
    if KNOWN: print(f"[=] known  = {KNOWN}  {'MATCH' if hexs==KNOWN else 'MISMATCH'}")
    # 오라클 검증: countread 가 출력하는 exit 코드 사용 (addr 는 아무거나)
    _,ec=countread(bytes(secret).hex(), RELA, want_exit=True)
    print(f"[=] oracle exit = {ec} ({'OK 정답!' if ec==0 else 'reject'})")

main()
