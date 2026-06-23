import struct

M = (1 << 64) - 1


def rol(x, n):
    n &= 63
    return ((x << n) | (x >> (64 - n))) & M if n else x & M


def ror(x, n):
    n &= 63
    return ((x >> n) | (x << (64 - n))) & M if n else x & M


def inv(a):
    # 2^64 모듈러 곱셈 역원 (a 는 홀수여야 함 -> ROT1/ROT2 전부 홀수)
    return pow(a, -1, 1 << 64)


# ---- 바이너리에서 추출한 상수 테이블 ----
KA = [0x123456789ABCDEF, 0xF0E0D0C0B0A0908, 0x1111111111111111, 0x2222222222222222,
      0x3333333333333333, 0x4444444444444444, 0x5555555555555555, 0x6666666666666666]
KB = [0xFEDCBA0987654321, 0x89ABCDEF01234567, 0xCAFEBABEDEADBEEF, 0xBADF00DDEADC0DE,
      0x13579BDF2468ACE0, 0xCAFEFACE12345678, 0xF0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0]
KC = [0xA0A0A0A0A0A0A0A, 0x1B1B1B1B1B1B1B1B, 0x2C2C2C2C2C2C2C2C, 0x3D3D3D3D3D3D3D3D,
      0x4E4E4E4E4E4E4E4E, 0x5F5F5F5F5F5F5F5F, 0x6060606060606060, 0x7171717171717171]
KC2 = KC[:]
ROT1 = [0x13, 0x15, 0x17, 0x19, 0x1B, 0x1D, 0x1F, 0x21]
ROT2 = [0x31, 0x33, 0x35, 0x37, 0x39, 0x3B, 0x3D, 0x3F]
MASK = [0xF0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0, 0xAAAAAAAA55555555, 0x55555555AAAAAAAA,
        0x1234567890ABCDEF, 0xFEDCBA9876543210, 0xF1E2D3C4B5A6978, 0x89ABCDEF01234567]
TARGET = [0x35EE0F56E5B71CA4, 0x3FFD40A16A1056FD, 0xCA5272E52C5BA31A, 0x6BC3120B92A71B25,
          0x104FD2F6C2B935A3, 0xF1B5CA3663B1B1D6, 0xCAE30B30DAD2AA08, 0x7586BB8DC13D6EBE]
byteA = [0x5, 0xB, 0x11, 0x17, 0x1D, 0x3, 0x7, 0xD]    # rol amounts (round1)
byteB = [0x8, 0x10, 0x18, 0x20, 0x4, 0xC, 0x14, 0x1C]  # ror amounts (round3)

AA = 0xAAAAAAAAAAAAAAAA   # odd-bit mask
A5 = 0x5555555555555555   # even-bit mask


def swap_pairs(v):
    # 라운드2: 짝수쌍(i,i+1) 끼리 even-bit(0x5555..) 교환, odd-bit 유지. (자기역원)
    out = v[:]
    for i in range(0, 8, 2):
        a, b = v[i], v[i + 1]
        out[i]     = (a & AA) | (b & A5)
        out[i + 1] = (b & AA) | (a & A5)
    return out


def forward(inp):
    """검증용: 입력 8 qword -> final 8 qword."""
    o6 = [0] * 8
    for i in range(8):                       # 라운드1
        o1 = (inp[i] + KA[i]) & M
        o2 = o1 ^ KB[i]
        o3 = rol(o2, byteA[i])
        o4 = (o3 * ROT1[i]) & M
        o6[i] = (~o4) & M
    p6 = swap_pairs(o6)                       # 라운드2
    fin = [0] * 8
    for i in range(8):                       # 라운드3
        t = (p6[i] + KC[i]) & M               # div/mod 재조합은 항등 -> 생략
        t = ror(t, byteB[i])
        t ^= MASK[i]
        t = (t * ROT2[i]) & M
        fin[i] = (t - KC2[i]) & M
    return fin


def invert(tgt):
    """TARGET -> 입력 8 qword 복원."""
    p6 = [0] * 8
    for i in range(8):                       # 라운드3 역
        t = (tgt[i] + KC2[i]) & M
        t = (t * inv(ROT2[i])) & M
        t ^= MASK[i]
        t = rol(t, byteB[i])                  # ror 의 역 = rol
        p6[i] = (t - KC[i]) & M
    o6 = swap_pairs(p6)                        # 라운드2 역(자기역원)
    inp = [0] * 8
    for i in range(8):                       # 라운드1 역
        o4 = (~o6[i]) & M
        o3 = (o4 * inv(ROT1[i])) & M
        o2 = ror(o3, byteA[i])                # rol 의 역 = ror
        o1 = o2 ^ KB[i]
        inp[i] = (o1 - KA[i]) & M
    return inp


if __name__ == "__main__":
    inp = invert(TARGET)
    flag = b"".join(struct.pack("<Q", x) for x in inp)
    assert forward(inp) == TARGET, "forward check failed"
    print("[+] forward(recovered) == TARGET : OK")
    print("[+] FLAG:", flag.decode())