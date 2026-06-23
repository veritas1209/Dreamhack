#!/usr/bin/env python3
# 사용: python3 patch_relasz.py main main_patched [new_relasz_hex]
# main 의 PT_DYNAMIC 에서 DT_RELA(7)/DT_RELASZ(8)/DT_RELAENT(9)/DT_PLTRELSZ(2) 출력 후
# DT_RELASZ 를 new 값으로 덮어써 저장. (기본 0x20000 — 과거 성공값)
import sys, struct
inp, outp = sys.argv[1], sys.argv[2]
new = int(sys.argv[3],16) if len(sys.argv)>3 else 0x20000
b = bytearray(open(inp,'rb').read())
assert b[:4]==b'\x7fELF' and b[4]==2, "ELF64 아님"
e_phoff   = struct.unpack_from('<Q', b, 0x20)[0]
e_phentsz = struct.unpack_from('<H', b, 0x36)[0]
e_phnum   = struct.unpack_from('<H', b, 0x38)[0]
dyn_off=dyn_sz=None
for i in range(e_phnum):
    base=e_phoff+i*e_phentsz
    p_type=struct.unpack_from('<I', b, base)[0]
    if p_type==2:  # PT_DYNAMIC
        dyn_off=struct.unpack_from('<Q', b, base+0x08)[0]
        dyn_sz =struct.unpack_from('<Q', b, base+0x20)[0]
        break
assert dyn_off is not None, "PT_DYNAMIC 없음"
TAG={1:'NEEDED',2:'PLTRELSZ',7:'RELA',8:'RELASZ',9:'RELAENT',0x17:'JMPREL',0x15:'DEBUG'}
relasz_pos=None
o=dyn_off
while o < dyn_off+dyn_sz:
    tag,val=struct.unpack_from('<QQ', b, o)
    if tag==0: break
    if tag in (2,7,8,9,0x17,0x15):
        print(f"  DT_{TAG.get(tag,hex(tag))} = {val:#x}  (@file {o:#x})")
    if tag==8: relasz_pos=o+8
    o+=16
assert relasz_pos is not None, "DT_RELASZ 없음"
old=struct.unpack_from('<Q', b, relasz_pos)[0]
struct.pack_into('<Q', b, relasz_pos, new)
open(outp,'wb').write(b)
print(f"[+] DT_RELASZ {old:#x} -> {new:#x}, wrote {outp}")
