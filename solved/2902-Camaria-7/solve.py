import sys

# 100% 순정 S-Box 생성
def generate_sboxes():
    exp = [1] * 256; log = [0] * 256
    for i in range(1, 256):
        j = (exp[i-1] << 1) ^ exp[i-1]
        if j & 0x100: j ^= 0x11b
        exp[i] = j
    for i in range(1, 255): log[exp[i]] = i

    A = [[1,0,0,0,1,1,1,1], [1,1,0,0,0,1,1,1], [1,1,1,0,0,0,1,1], [1,1,1,1,0,0,0,1],
         [1,1,1,1,1,0,0,0], [0,1,1,1,1,1,0,0], [0,0,1,1,1,1,1,0], [0,0,0,1,1,1,1,1]]
    B = [[0,1,0,1,1,1,1,0], [0,0,1,1,1,1,0,1], [1,1,0,1,0,1,1,1], [1,0,0,1,1,1,0,1],
         [0,0,1,0,1,1,0,0], [1,0,0,0,0,0,0,1], [0,1,0,1,1,1,0,1], [1,1,0,1,0,0,1,1]]

    S1, S2, X1, X2 = bytearray(256), bytearray(256), bytearray(256), bytearray(256)
    for i in range(256):
        p = 0 if i == 0 else exp[255 - log[i]]; t = 0
        for j in range(8):
            s = 0
            for k in range(8):
                if (p >> (7-k)) & 1: s ^= A[k][j]
            t = (t << 1) ^ s
        t ^= 0x63; S1[i] = t; X1[t] = i

    for i in range(256):
        p = 0 if i == 0 else exp[(247 * log[i]) % 255]; t = 0
        for j in range(8):
            s = 0
            for k in range(8):
                if (p >> k) & 1: s ^= B[7-j][k]
            t = (t << 1) ^ s
        t ^= 0xe2; S2[i] = t; X2[t] = i
    return S1, S2, X1, X2

S1, S2, X1, X2 = generate_sboxes()
KRK = [bytes.fromhex("517cc1b727220a94fe13abe8fa9a6ee0"), bytes.fromhex("6db14acc9e21c820ff28b1d5ef5de2b0"), bytes.fromhex("db92371d2126e9700324977504e8c90e")]

def xor16(a, b): return bytearray(x ^ y for x, y in zip(a, b))
def rot128(b, bits): val = int.from_bytes(b, 'big'); val = ((val >> (bits%128)) | (val << (128 - (bits%128)))) & ((1 << 128) - 1); return val.to_bytes(16, 'big')

def mix_columns(st):
    out = bytearray(16)
    out[0] = st[3]^st[4]^st[6]^st[8]^st[9]^st[13]^st[14]; out[1] = st[2]^st[5]^st[7]^st[8]^st[9]^st[12]^st[15]
    out[2] = st[1]^st[4]^st[6]^st[10]^st[11]^st[12]^st[15]; out[3] = st[0]^st[5]^st[7]^st[10]^st[11]^st[13]^st[14]
    out[4] = st[0]^st[2]^st[5]^st[8]^st[11]^st[14]^st[15]; out[5] = st[1]^st[3]^st[4]^st[9]^st[10]^st[14]^st[15]
    out[6] = st[0]^st[2]^st[7]^st[9]^st[10]^st[12]^st[13]; out[7] = st[1]^st[3]^st[6]^st[8]^st[11]^st[12]^st[13]
    out[8] = st[0]^st[1]^st[4]^st[7]^st[10]^st[13]^st[15]; out[9] = st[0]^st[1]^st[5]^st[6]^st[11]^st[12]^st[14]
    out[10] = st[2]^st[3]^st[5]^st[6]^st[8]^st[13]^st[15]; out[11] = st[2]^st[3]^st[4]^st[7]^st[9]^st[12]^st[14]
    out[12] = st[1]^st[2]^st[6]^st[7]^st[9]^st[11]^st[12]; out[13] = st[0]^st[3]^st[6]^st[7]^st[8]^st[10]^st[13]
    out[14] = st[0]^st[3]^st[4]^st[5]^st[9]^st[11]^st[14]; out[15] = st[1]^st[2]^st[4]^st[5]^st[8]^st[10]^st[15]
    return out

def sbox_layer_t1(st):
    out = bytearray(16)
    for i in range(4): out[i*4]=S1[st[i*4]]; out[i*4+1]=S2[st[i*4+1]]; out[i*4+2]=X1[st[i*4+2]]; out[i*4+3]=X2[st[i*4+3]]
    return out

def sbox_layer_t2(st):
    out = bytearray(16)
    for i in range(4): out[i*4]=X1[st[i*4]]; out[i*4+1]=X2[st[i*4+1]]; out[i*4+2]=S1[st[i*4+2]]; out[i*4+3]=S2[st[i*4+3]]
    return out

def generate_round_keys(mk, key_size):
    w0 = bytearray(mk[:16])
    if key_size == 128: w1 = bytearray(16)
    elif key_size == 256: w1 = bytearray(mk[16:32])
    else: w1 = bytearray(16)
    
    q = (key_size - 128) // 64
    t0 = xor16(w0, KRK[q])
    t = mix_columns(sbox_layer_t1(t0)); w1 = xor16(w1, t)
    
    q = 0 if q == 2 else q + 1
    t = mix_columns(sbox_layer_t2(xor16(w1, KRK[q]))); w2 = xor16(t, w0)
    
    q = 0 if q == 2 else q + 1
    t = mix_columns(sbox_layer_t1(xor16(w2, KRK[q]))); w3 = xor16(t, w1)
    
    rk = [
        xor16(w0, rot128(w1, 19)), xor16(w1, rot128(w2, 19)), xor16(w2, rot128(w3, 19)), xor16(w3, rot128(w0, 19)),
        xor16(w0, rot128(w1, 31)), xor16(w1, rot128(w2, 31)), xor16(w2, rot128(w3, 31)), xor16(w3, rot128(w0, 31)),
        xor16(w0, rot128(w1, 67)), xor16(w1, rot128(w2, 67)), xor16(w2, rot128(w3, 67)), xor16(w3, rot128(w0, 67)),
        xor16(w0, rot128(w1, 97))
    ]
    if key_size > 128:
        rk.append(xor16(w1, rot128(w2, 97)))
        rk.append(xor16(w2, rot128(w3, 97)))
    if key_size > 192:
        rk.append(xor16(w3, rot128(w0, 97)))
        rk.append(xor16(w0, rot128(w1, 109)))
    return rk

def encrypt_block(data, ek, rounds):
    state = bytearray(data)
    for r in range(rounds):
        state = xor16(state, ek[r])
        if r % 2 == 0: state = sbox_layer_t1(state)
        else:          state = sbox_layer_t2(state)
        if r != rounds - 1: state = mix_columns(state)
    return xor16(state, ek[rounds])

def swap_endian(b):
    out = bytearray(len(b))
    for i in range(0, len(b), 4):
        out[i] = b[i+3]; out[i+1] = b[i+2]; out[i+2] = b[i+1]; out[i+3] = b[i]
    return out

if __name__ == "__main__":
    P1 = b"AAAAAAAAAAAAAAAA"
    IV = bytes.fromhex("cc7f688734e770dec3140142ffae82ab")
    C1_TARGET = bytes.fromhex("51b1cca1f6c3f06093962292727ddd0d")

    # 모든 경우의 수를 테스트합니다.
    keys_to_test = [
        ("Key: cc7f... (Hex 16 bytes) ARIA-128", bytes.fromhex("cc7f688734e770dec3140142ffae82ab"), 128),
        ("Key: cc7f... (ASCII 32 bytes) ARIA-256", b"cc7f688734e770dec3140142ffae82ab", 256),
        ("Key: AAAA... (Hex 16 bytes = 0xaa) ARIA-128", bytes.fromhex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 128),
        ("Key: AAAA... (ASCII 32 bytes = 0x41) ARIA-256", b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 256)
    ]

    print("\n[🔥] 100% PURE ARIA KPA Key Bruteforcer [🔥]")
    print(f"[*] Target Cipher : {C1_TARGET.hex().upper()}\n")

    found = False
    for name, mk, size in keys_to_test:
        rounds = 12 if size == 128 else 16
        
        # Standard Endian
        ek = generate_round_keys(mk, size)
        c_cbc = encrypt_block(xor16(P1, IV), ek, rounds)
        c_ecb = encrypt_block(P1, ek, rounds)
        
        # Little Endian
        mk_le = swap_endian(mk)
        ek_le = generate_round_keys(mk_le, size)
        P1_le = swap_endian(P1)
        IV_le = swap_endian(IV)
        c_cbc_le = swap_endian(encrypt_block(xor16(P1_le, IV_le), ek_le, rounds))
        c_ecb_le = swap_endian(encrypt_block(P1_le, ek_le, rounds))

        results = {
            "CBC Standard": c_cbc,
            "ECB Standard": c_ecb,
            "CBC Little Endian": c_cbc_le,
            "ECB Little Endian": c_ecb_le
        }

        for mode, result in results.items():
            if result == C1_TARGET:
                print(f"[✅ BINGO!!!] 완벽하게 일치합니다!")
                print(f" -> {name}")
                print(f" -> Mode: {mode}")
                found = True

    if not found:
        print("[-] 일치하는 키가 없습니다. 출제자가 이 중 하나를 다시 변형한 것이 틀림없습니다.")