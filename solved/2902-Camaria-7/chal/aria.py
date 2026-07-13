"""Pure-python ARIA (RFC 5794). Validated against RFC test vectors."""

# --- AES S-box (SB1) ---
def _aes_sbox():
    p=1; q=1; sbox=[0]*256
    # generate using the standard method
    sbox[0]=0x63
    # use known constant table instead for reliability
    table = bytes.fromhex(
      "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
      "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
      "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
      "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
      "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
      "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
      "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
      "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
    return list(table)
SB1 = _aes_sbox()
SB3 = [0]*256
for i,v in enumerate(SB1): SB3[v]=i   # inverse AES sbox

SB2 = [
0xe2,0x4e,0x54,0xfc,0x94,0xc2,0x4a,0xcc,0x62,0x0d,0x6a,0x46,0x3c,0x4d,0x8b,0xd1,
0x5e,0xfa,0x64,0xcb,0xb4,0x97,0xbe,0x2b,0xbc,0x77,0x2e,0x03,0xd3,0x19,0x59,0xc1,
0x1d,0x06,0x41,0x6b,0x55,0xf0,0x99,0x69,0xea,0x9c,0x18,0xae,0x63,0xdf,0xe7,0xbb,
0x00,0x73,0x66,0xfb,0x96,0x4c,0x85,0xe4,0x3a,0x09,0x45,0xaa,0x0f,0xee,0x10,0xeb,
0x2d,0x7f,0xf4,0x29,0xac,0xcf,0xad,0x91,0x8d,0x78,0xc8,0x95,0xf9,0x2f,0xce,0xcd,
0x08,0x7a,0x88,0x38,0x5c,0x83,0x2a,0x28,0x47,0xdb,0xb8,0xc7,0x93,0xa4,0x12,0x53,
0xff,0x87,0x0e,0x31,0x36,0x21,0x58,0x48,0x01,0x8e,0x37,0x74,0x32,0xca,0xe9,0xb1,
0xb7,0xab,0x0c,0xd7,0xc4,0x56,0x42,0x26,0x07,0x98,0x60,0xd9,0xb6,0xb9,0x11,0x40,
0xec,0x20,0x8c,0xbd,0xa0,0xc9,0x84,0x04,0x49,0x23,0xf1,0x4f,0x50,0x1f,0x13,0xdc,
0xd8,0xc0,0x9e,0x57,0xe3,0xc3,0x7b,0x65,0x3b,0x02,0x8f,0x3e,0xe8,0x25,0x92,0xe5,
0x15,0xdd,0xfd,0x17,0xa9,0xbf,0xd4,0x9a,0x7e,0xc5,0x39,0x67,0xfe,0x76,0x9d,0x43,
0xa7,0xe1,0xd0,0xf5,0x68,0xf2,0x1b,0x34,0x70,0x05,0xa3,0x8a,0xd5,0x79,0x86,0xa8,
0x30,0xc6,0x51,0x4b,0x1e,0xa6,0x27,0xf6,0x35,0xd2,0x6e,0x24,0x16,0x82,0x5f,0xda,
0xe6,0x75,0xa2,0xef,0x2c,0xb2,0x1c,0x9f,0x5d,0x6f,0x80,0x0a,0x72,0x44,0x9b,0x6c,
0x90,0x0b,0x5b,0x33,0x7d,0x5a,0x52,0xf3,0x61,0xa1,0xf7,0xb0,0xd6,0x3f,0x7c,0x6d,
0xed,0x14,0xe0,0xa5,0x3d,0x22,0xb3,0xf8,0x89,0xde,0x71,0x1a,0xaf,0xba,0xb5,0x81,
]
SB4 = [0]*256
for i,v in enumerate(SB2): SB4[v]=i   # inverse of SB2

def SL1(x):
    s=(SB1,SB2,SB3,SB4)
    return bytes(s[i&3][x[i]] for i in range(16))
def SL2(x):
    s=(SB3,SB4,SB1,SB2)
    return bytes(s[i&3][x[i]] for i in range(16))

def A(x):
    x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15 = x
    return bytes([
      x3^x4^x6^x8^x9^x13^x14,
      x2^x5^x7^x8^x9^x12^x15,
      x1^x4^x6^x10^x11^x12^x15,
      x0^x5^x7^x10^x11^x13^x14,
      x0^x2^x5^x8^x11^x14^x15,
      x1^x3^x4^x9^x10^x14^x15,
      x0^x2^x7^x9^x10^x12^x13,
      x1^x3^x6^x8^x11^x12^x13,
      x0^x1^x4^x7^x10^x13^x15,
      x0^x1^x5^x6^x11^x12^x14,
      x2^x3^x5^x6^x8^x13^x15,
      x2^x3^x4^x7^x9^x12^x14,
      x1^x2^x6^x7^x9^x11^x12,
      x0^x3^x6^x7^x8^x10^x13,
      x0^x3^x4^x5^x9^x11^x14,
      x1^x2^x4^x5^x8^x10^x15,
    ])

def FO(x): return A(SL1(x))
def FE(x): return A(SL2(x))

def _xor(a,b): return bytes(i^j for i,j in zip(a,b))

MASK=(1<<128)-1
def _ror(v,n): return ((v>>n)|(v<<(128-n)))&MASK
def i2b(v): return v.to_bytes(16,'big')
def b2i(b): return int.from_bytes(b,'big')

C1=0x517cc1b727220a94fe13abe8fa9a6ee0
C2=0x6db14acc9e21c820ff28b1d5ef5de2b0
C3=0xdb92371d2126e9700324977504e8c90e

def expand(mk):
    klen=len(mk)*8
    KL=mk[:16]
    KR=(mk[16:]+b'\x00'*16)[:16]
    if klen==128: CK1,CK2,CK3=C1,C2,C3; rounds=12
    elif klen==192: CK1,CK2,CK3=C2,C3,C1; rounds=14
    else: CK1,CK2,CK3=C3,C1,C2; rounds=16
    W0=KL
    W1=_xor(FO(_xor(W0,i2b(CK1))),KR)
    W2=_xor(FE(_xor(W1,i2b(CK2))),W0)
    W3=_xor(FO(_xor(W2,i2b(CK3))),W1)
    w0,w1,w2,w3=b2i(W0),b2i(W1),b2i(W2),b2i(W3)
    ek=[]
    ek.append(w0 ^ _ror(w1,19))
    ek.append(w1 ^ _ror(w2,19))
    ek.append(w2 ^ _ror(w3,19))
    ek.append(_ror(w0,19) ^ w3)
    ek.append(w0 ^ _ror(w1,31))
    ek.append(w1 ^ _ror(w2,31))
    ek.append(w2 ^ _ror(w3,31))
    ek.append(_ror(w0,31) ^ w3)
    ek.append(w0 ^ _ror(w1,67))
    ek.append(w1 ^ _ror(w2,67))
    ek.append(w2 ^ _ror(w3,67))
    ek.append(_ror(w0,67) ^ w3)
    ek.append(w0 ^ _ror(w1,97))
    ek.append(w1 ^ _ror(w2,97))
    ek.append(w2 ^ _ror(w3,97))
    ek.append(_ror(w0,97) ^ w3)
    ek.append(w0 ^ _ror(w1,109))
    return [i2b(e) for e in ek], rounds

def encrypt_block(mk, pt):
    ek,rounds=expand(mk)
    s=pt
    for i in range(1,rounds):   # rounds-1 full rounds
        s=_xor(s,ek[i-1])
        s=FO(s) if (i&1) else FE(s)
    # final round: SL (opposite of what FE would be) without A
    s=_xor(s,ek[rounds-1])
    s=SL2(s)
    s=_xor(s,ek[rounds])
    return s

if __name__=='__main__':
    # RFC 5794 128-bit test vector
    key=bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    pt =bytes.fromhex('00112233445566778899aabbccddeeff')
    ct =encrypt_block(key,pt)
    print('128 ct:',ct.hex(),'expected d718fbd6ab644c739da95f3be6451778', ct.hex()=='d718fbd6ab644c739da95f3be6451778')
    # 192-bit vector
    key=bytes.fromhex('000102030405060708090a0b0c0d0e0f1011121314151617')
    ct=encrypt_block(key,pt)
    print('192 ct:',ct.hex(),'expected 26449c1805dbe7aa25a468ce263a9e79', ct.hex()=='26449c1805dbe7aa25a468ce263a9e79')
    # 256-bit vector
    key=bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    ct=encrypt_block(key,pt)
    print('256 ct:',ct.hex(),'expected f92bd7c79fb72e2f2b8f80c1972d24fc', ct.hex()=='f92bd7c79fb72e2f2b8f80c1972d24fc')
