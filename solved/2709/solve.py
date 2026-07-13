#!/usr/bin/env python3
# ============================================================================
#  CTF: After the Last Step  (reversing)
#  FLAG 형식: INCOGNITO{...}
#
#  핵심 통찰:
#    프로그램은 레지스트리(HKCU\Software\IncognitoCTF\AfterTheLastStep)에
#    상태를 저장하는 3단계 상태머신이다. 각 단계의 입력 검증에는
#    BCryptGenRandom 으로 만든 랜덤 ID가 섞여 있지만, 최종 복호화 키를
#    구성하는 값(Gate / Seal)은 전부 바이너리 상수로부터 '결정적으로'
#    계산된다. 따라서 실제로 프로그램을 실행하지 않고도 키를 정적으로
#    재구성하여 FLAG를 복호화할 수 있다. ("only the final state matters")
#
#  사용법: python3 solve.py [path_to_exe]
# ============================================================================
import sys, struct, hashlib, zlib

EXE_PATH = sys.argv[1] if len(sys.argv) > 1 else "after_the_last_step.exe"

# ---------------------------------------------------------------------------
# .rdata 섹션에서 VMA 기준으로 바이트를 읽어오는 헬퍼
#   .rdata: file offset 0x2C00, VMA 0x140004000
# ---------------------------------------------------------------------------
DATA = open(EXE_PATH, "rb").read()

def rdata(vma: int, n: int) -> bytes:
    foff = 0x2C00 + (vma - 0x140004000)
    return DATA[foff:foff + n]

# ---------------------------------------------------------------------------
# 암호 프리미티브
# ---------------------------------------------------------------------------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def crc_noinv(b: bytes) -> int:
    """반전 다항식(0xEDB88320) CRC32, 최종 XOR(0xFFFFFFFF) 미적용.
       init=0xFFFFFFFF 일 때 내부 상태 = zlib.crc32(b) ^ 0xFFFFFFFF."""
    return zlib.crc32(b) ^ 0xFFFFFFFF

def crc_std(b: bytes) -> int:
    """표준 CRC32 (최종 XOR 적용) = zlib.crc32."""
    return zlib.crc32(b) & 0xFFFFFFFF

p32 = lambda v: struct.pack("<I", v & 0xFFFFFFFF)   # 32bit little-endian

# ---------------------------------------------------------------------------
# 바이너리 내 데이터 (모두 0x140004310 근방의 .rdata 상수)
# ---------------------------------------------------------------------------
GATE_BLOCK = rdata(0x140004310, 0x40)   # 64B  -> gateSig 계산용
SEAL_BLOCK = rdata(0x140004350, 0x40)   # 64B  -> sealSig 계산용
BUF_SRC    = rdata(0x140004310, 0x80)   # 128B -> buf(SHA256) 입력
CIPHERTEXT = rdata(0x140004390, 39)     # 39B  -> FLAG 암호문

# ---------------------------------------------------------------------------
# 결정적 키 유도 체인 (main / stage0 / stage1 / stage2 를 정적으로 재현)
# ---------------------------------------------------------------------------
# main:  buf = SHA256(128B),  두 개의 서명값(gateSig / sealSig) 계산
buf     = sha256(BUF_SRC)
gateSig = crc_noinv(GATE_BLOCK) ^ 0xE4E6B11E     # main: r9=0 -> 최종반전 X
sealSig = crc_std(SEAL_BLOCK)   ^ 0x4775CD8F     # main: r9=1 -> 표준 CRC

# stage0:  Gate = GATEP_hash XOR MASKG_hash  ->  복원하면 GATEP_hash
GATEP   = sha256(b"GATEP" + buf + p32(gateSig) + p32(sealSig))

# stage1:  Seal = (SEALP_hash XOR MASKS_hash)[:16]  ->  복원하면 SEALP_hash[:16]
SEALP   = sha256(b"SEALP" + GATEP + buf)
SEALP16 = SEALP[:16]

# stage2:  FLAGKEY 입력에 들어가는 보조값 esi
esi      = crc_noinv(GATEP + SEALP16 + buf) ^ 0x5A5A5A5A

# stage2:  최종 복호화 키
flag_key = sha256(b"FLAGKEY" + buf + GATEP + SEALP16 + p32(esi))

# ---------------------------------------------------------------------------
# 복호화: 커스텀 SHA256-CTR 스트림 암호
#   블록 n 마다 keystream = SHA256(key || uint32_LE(n)),  plain = cipher XOR ks
# ---------------------------------------------------------------------------
def decrypt(key: bytes, ct: bytes) -> bytes:
    out, off, n = bytearray(), 0, 0
    while off < len(ct):
        ks = sha256(key + p32(n))
        out += bytes(c ^ k for c, k in zip(ct[off:off + 32], ks))
        off += 32
        n   += 1
    return bytes(out)

flag = decrypt(flag_key, CIPHERTEXT)

# ---------------------------------------------------------------------------
# 결과 출력
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"buf      = {buf.hex()}")
    print(f"gateSig  = {gateSig:08x}")
    print(f"sealSig  = {sealSig:08x}")
    print(f"GATEP    = {GATEP.hex()}")
    print(f"SEALP16  = {SEALP16.hex()}")
    print(f"esi      = {esi:08x}")
    print(f"flag_key = {flag_key.hex()}")
    print("-" * 50)
    print("FLAG:", flag.decode(errors="replace"))
