#!/usr/bin/env python3
# realdump/bin_N 의 .rela.p (reloc-TM 코드) 를 사람 읽기 좋게 통째 덤프
# 사용: python3 dump_relatm.py realdump/bin_5 > bin_5_tm.txt
import sys, struct
TYPES={1:'R_64',5:'COPY',6:'GLOB_DAT',7:'JMP_SLOT',8:'RELATIVE',0x21:'SIZE64',0x26:'R64_REL'}
def decode_code(add):  # addend 를 8B 코드로 보고 의미 짚기
    by=struct.pack('<q',add)
    if by[0]==0x48 and by[1]==0x83 and by[2]==0xc3 and by[4]==0xc3: return f"add rbx,{by[3]:#x};ret"
    if by[0]==0x48 and by[1]==0x83 and by[2]==0xeb and by[4]==0xc3: return f"sub rbx,{by[3]:#x};ret"
    if by[0]==0x48 and by[1]==0x81 and by[2]==0xc3: 
        v=struct.unpack_from('<I',by,3)[0]; return f"add rbx,{v:#x};ret"
    if by[0]==0x48 and by[1]==0x81 and by[2]==0xeb:
        v=struct.unpack_from('<I',by,3)[0]; return f"sub rbx,{v:#x};ret"
    return ""
path=sys.argv[1]
b=open(path,'rb').read()
# 동적에서 RELA off/size 읽기 (런타임 패치된 RELASZ 포함)
relasz=struct.unpack_from('<Q',b,0x2f30)[0]
rela_off=0x5000
n=relasz//24
print(f"# {path}  RELASZ={relasz:#x}  entries={n}")
print(f"# idx | r_offset            r_info       type  sym | addend                 decode")
# .sym.p 도 같이 읽기(sym idx -> st_value 매핑)
sym_off=0x4000
def sym(idx):
    o=sym_off+idx*24
    if o+24>len(b): return None
    name,info,other,shndx,value,size=struct.unpack_from('<IBBHQQ',b,o)
    return value
for i in range(n):
    o,info,add=struct.unpack_from('<QQq',b,rela_off+i*24)
    t=info & 0xffffffff; s=info>>32
    tn=TYPES.get(t,hex(t))
    dec=decode_code(add)
    sv=sym(s) if s else None
    extra=f" sym{s}.val={sv:#x}" if sv else ""
    print(f"{i:5d} | {o:#018x}  {info:#018x}  {tn:8} {s:3d} | {add & 0xffffffffffffffff:#018x}  {dec}{extra}")
