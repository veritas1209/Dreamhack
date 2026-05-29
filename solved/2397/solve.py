import struct
M = (1<<64)-1

SBOX = [int(x,16) for x in """
63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79 e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
""".split()]
INV_SBOX=[0]*256
for i,v in enumerate(SBOX): INV_SBOX[v]=i

def gmul(a,b):
    p=0
    for _ in range(8):
        if b&1: p^=a
        hi=a&0x80; a=(a<<1)&0xff
        if hi: a^=0x1b
        b>>=1
    return p

# ---- AES building blocks matching the decompiled byte indexing (column-major) ----
SR  = {0:0,4:4,8:8,12:12, 1:5,5:9,9:13,13:1, 2:10,6:14,10:2,14:6, 3:15,7:3,11:7,15:11}  # out[i]=in[SR[i]]
def sub_bytes(s):  return [SBOX[x] for x in s]
def inv_sub(s):    return [INV_SBOX[x] for x in s]
def shift_rows(s): return [s[SR[i]] for i in range(16)]
ISR={v:k for k,v in SR.items()}
def inv_shift_rows(s): return [s[ISR[i]] for i in range(16)]
def mix_cols(s):
    o=s[:]
    for c in range(4):
        a=s[c*4:c*4+4]
        o[c*4+0]=gmul(2,a[0])^gmul(3,a[1])^a[2]^a[3]
        o[c*4+1]=a[0]^gmul(2,a[1])^gmul(3,a[2])^a[3]
        o[c*4+2]=a[0]^a[1]^gmul(2,a[2])^gmul(3,a[3])
        o[c*4+3]=gmul(3,a[0])^a[1]^a[2]^gmul(2,a[3])
    return o
def inv_mix(s):
    o=s[:]
    for c in range(4):
        a=s[c*4:c*4+4]
        o[c*4+0]=gmul(14,a[0])^gmul(11,a[1])^gmul(13,a[2])^gmul(9,a[3])
        o[c*4+1]=gmul(9,a[0])^gmul(14,a[1])^gmul(11,a[2])^gmul(13,a[3])
        o[c*4+2]=gmul(13,a[0])^gmul(9,a[1])^gmul(14,a[2])^gmul(11,a[3])
        o[c*4+3]=gmul(11,a[0])^gmul(13,a[1])^gmul(9,a[2])^gmul(14,a[3])
    return o

def F08556(b):  # SB,SR,MC,SB,SR,MC
    b=mix_cols(shift_rows(sub_bytes(b)))
    b=mix_cols(shift_rows(sub_bytes(b)))
    return b
def invF08556(b):
    b=inv_sub(inv_shift_rows(inv_mix(b)))
    b=inv_sub(inv_shift_rows(inv_mix(b)))
    return b

# verify inverses round-trip
import os
t=list(os.urandom(16))
assert invF08556(F08556(t))==t, "08556 inverse FAIL"
print("[ok] invF08556 round-trip verified")
print("[ok] SBOX/inv consistent:", all(INV_SBOX[SBOX[i]]==i for i in range(256)))

# ---- decode known constants from main (DAT=0 => literal) ----
key_consts   = [0x08,0x3c,0x96,0x53,0x8d,0x28,0xce,0x51,0x67,0x61,0x98,0x82,0xaa,0xe6,0xcb,0x20,
                0x75,0x7f,0xc0,0xee,0x6c,0x33,0xaa,0xd5,0x5f,0xca,0x22,0x8f,0x6f,0xa6,0x41,0x30]
nonce_consts = [0x96,0x66,0x85,0x10,0x53,0x74,0xa7,0xad,0xc9,0x42,0x34,0x3a,0x88,0x91,0xd5,0x9f]
ct_consts    = [0x29,0xb4,0x8e,0x3e,0x23,0x87,0x9a,0xf0,0x28,0x46,0xae,0x45,0x54,0x5e,0x78,0x18,
                0x66,0x64,0x05,0x82,0x67,0x95,0x01,0x65,0x5c,0xf2,0x6a,0x7c,0x27,0xc7,0xa6,0x34,
                0x19,0x7e,0x28,0x0c,0x04,0x6b,0x74,0x01,0x2a,0x20,0xd9,0x39,0x48,0x96,0x7e,0x19,
                0xa9,0xae,0x5e,0x5a,0xb4,0xe5,0xf8,0x50,0xa1,0x8a,0x6c,0x3a,0xdf,0xbd,0xf0,0x72]
KEY=bytes(key_consts); NONCE=bytes(nonce_consts); CT=bytes(ct_consts); AD=b"this-message-is-flag"
print("key  =",KEY.hex()); print("nonce=",NONCE.hex()); print("CT   =",CT.hex()); print("len(CT)=",len(CT))

# ====== UNKNOWNS to be dumped from the binary ======
IV = [0x504f444f2d323536, 0x2d41454144202d31, 0x1, 0x6b736b2d61727821]                 # 4 x u64 at DAT_00122080  (little-endian words)
RC = [0x9e3779b97f4a7c15, 0xc2b2ae3d27d4eb4f, 0x165667b19e3779f9, 0x85ebca77c2b2ae63]                 # DAT_00122060, _68, _70, _78
# ===================================================

def rotl(x,n): n&=63; return ((x<<n)|(x>>(64-n)))&M if n else x&M
def P(s):
    a,b,c,d=s
    for i in range(8):
        x=rotl(d ^ ((a+b)&M), 32)
        y=rotl(b ^ ((c+x)&M), 24)
        a=(a+b+y)&M
        d=rotl((x^a)&M, 16)
        c=(c+x+d)&M
        b=rotl((y^c)&M, 63)
        a ^= RC[0]^i
        b ^= RC[1]^((i<<32)&M)
        c ^= RC[2]^((i*0x9e37)&M)
        d ^= RC[3]^((i*0x7f4a)&M)
        a&=M;b&=M;c&=M;d&=M
    return [a,b,c,d]
def ld(b,o): return int.from_bytes(b[o:o+8],'little')
def absorb(s,block16):
    s[0]^=ld(block16,0); s[1]^=ld(block16,8); return P(s)
def absorb_final(s,data):  # pad 0x80
    blk=bytearray(16); blk[:len(data)]=data; blk[len(data)]^=0x80
    return absorb(s,bytes(blk))

def decrypt():
    s=[IV[k]^ld(KEY,8*k) for k in range(4)]
    s[0]^=ld(NONCE,0); s[1]^=ld(NONCE,8); s=P(s)
    s[3]^=0xAD
    s=absorb(s,AD[:16]); s=absorb_final(s,AD[16:])
    s[3]^=0x3C
    flag=bytearray()
    for i in range(0,len(CT),16):
        s=P(s)
        ks=struct.pack('<Q',s[0])+struct.pack('<Q',s[1])
        cblk=CT[i:i+16]
        inner=bytes(invF08556(list(cblk)))
        flag+=bytes(p^k for p,k in zip(inner,ks))
        s=absorb(s,cblk)
    return bytes(flag)

print("\nrecovered:", decrypt())