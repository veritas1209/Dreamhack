#!/usr/bin/env python3
"""
Homemade Cipher (WaRP) - 최종 복호화 / 공격 스크립트

암호 구조 (cipher.py 분해):
    key[c] = base_{b,c,d}[ (key[x] + a) ] - a   (mod 256)
  - (a,b,c,d) = (nonce + 위치)의 하위->상위 바이트
  - base_{b,c,d} 는 공개된 s-box(s1~s4, r)만으로 계산 가능
  - 비밀은 key(256 순열)와 nonce(32bit) 뿐

공격 핵심 ("엔트로피 공격"):
  평문이 단색 배경 BMP라서 같은 채널의 배경 픽셀은 key[배경값]이 상수.
  -> 배경 픽셀들의 '암호문 충돌 패턴'이 key와 무관하게 nonce에만 의존
  -> k-free 검사로 nonce를 전수조사로 복구한 뒤, 배경 앵커로 key 전체를 복원.

사용법:
    python3 solve.py flag_bmp.enc                 # nonce 모를 때: 전수조사 후 복호화
    python3 solve.py flag_bmp.enc --nonce 1521696479   # nonce 알 때: 즉시 복호화
"""
import sys, struct, argparse, functools
from collections import Counter, defaultdict
from cipher import Cipher   # 같은 폴더의 cipher.py

# ---- 공개 박스 가져오기 (cipher.py 의 s-box / 역박스) ----
_ref = Cipher(list(range(256)), 0)
s1, s2, s3, s4, r = _ref.s1, _ref.s2, _ref.s3, _ref.s4, _ref.r
S1, S2, S3, S4 = _ref.S1, _ref.S2, _ref.S3, _ref.S4

@functools.lru_cache(maxsize=None)
def base_table(b, c, d):
    """base_{b,c,d}: a=0 기준의 정방향 변환표 (공개 박스만 사용)."""
    out = [0] * 256
    for X in range(256):
        i = s1[X]
        i = s2[(i + b) % 256]
        i = s3[(i + c) % 256]
        i = s4[(i + d) % 256]
        i = r[i]
        i = (S4[i] - d) % 256
        i = (S3[i] - c) % 256
        i = (S2[i] - b) % 256
        i = S1[i]
        out[X] = i
    return tuple(out)

def ctr_bytes(nonce, pos):
    ctr = (nonce + pos) & 0xFFFFFFFF
    return ctr & 0xFF, (ctr >> 8) & 0xFF, (ctr >> 16) & 0xFF, (ctr >> 24) & 0xFF


# ---------------------------------------------------------------
# 1) nonce 복구 (순수 파이썬, 검증용/이식용. 느리면 C 버전 사용 권장)
# ---------------------------------------------------------------
def build_collision_pairs(body, span=1024, channel=0, max_pairs=14):
    """첫 span 바이트에서 지정 채널의 '같은 암호문 바이트' 충돌쌍을 수집."""
    positions = [(54 + i, body[i]) for i in range(channel, span, 3)]
    groups = defaultdict(list)
    for p, cv in positions:
        groups[cv].append(p)
    pairs = []
    for ps in groups.values():
        for j in range(1, len(ps)):
            pairs.append((ps[0], ps[j]))
    # 분리 거리가 큰 쌍(=제약이 강한 쌍) 우선
    pairs.sort(key=lambda ab: -abs(ab[1] - ab[0]))
    return pairs[:max_pairs]

def nonce_is_consistent(nonce, pairs):
    """
    충돌쌍 전부를 만족하는 공통 V(=key[배경])가 존재하면 True.
    조건: base_A[(V+aa)]-aa == base_B[(V+ab)]-ab  (모든 쌍)
    """
    allowed = set(range(256))
    for pa, pb in pairs:
        aa_, ba_, ca_, da_ = ctr_bytes(nonce, pa)
        ab_, bb_, cb_, db_ = ctr_bytes(nonce, pb)
        btA = base_table(ba_, ca_, da_)
        btB = base_table(bb_, cb_, db_)
        ok = set()
        for V in range(256):
            if (btA[(V + aa_) % 256] - aa_) % 256 == (btB[(V + ab_) % 256] - ab_) % 256:
                ok.add(V)
        allowed &= ok
        if not allowed:
            return False
    return True

def recover_nonce_python(body, start=0, end=1 << 32):
    """순수 파이썬 전수조사 (느림! 실전은 brute8.c 사용 권장)."""
    pairs = build_collision_pairs(body)
    for nonce in range(start, end):
        if nonce_is_consistent(nonce, pairs):
            return nonce
    return None


# ---------------------------------------------------------------
# 2) nonce 가 정해지면 key 전체 복원 후 복호화
# ---------------------------------------------------------------
def find_channel_V(body, nonce, ch, sample=6000):
    """채널 ch 의 배경값 V = key[배경] 을 일관성으로 결정."""
    best = (10**9, None)
    for V in range(256):
        seen, viol = {}, 0
        for i in range(ch, min(len(body), sample), 3):
            a, b, c, d = ctr_bytes(nonce, 54 + i)
            kc = (base_table(b, c, d)[(V + a) % 256] - a) % 256
            cv = body[i]
            if cv in seen:
                if seen[cv] != kc:
                    viol += 1
            else:
                seen[cv] = kc
        if viol < best[0]:
            best = (viol, V)
    return best  # (violations, V)

def recover_key(body, nonce, Vch):
    """
    배경 가정 + 다수결로 순열 key 전체 복원.
    배경 픽셀: key[c] = base_{bcd}[(V_ch + a)] - a
    각 암호문 바이트 c 는 대부분 배경에서 유래하므로 다수결이 참값.
    """
    votes = defaultdict(Counter)
    for i in range(len(body)):
        ch = i % 3
        a, b, c, d = ctr_bytes(nonce, 54 + i)
        kc = (base_table(b, c, d)[(Vch[ch] + a) % 256] - a) % 256
        votes[body[i]][kc] += 1
    key = [votes[cv].most_common(1)[0][0] for cv in range(256)]
    assert sorted(key) == list(range(256)), "key가 순열이 아님 — nonce/V 확인 필요"
    return key

def decrypt(ct, key, nonce):
    # cipher.decrypt == encrypt (동일 키스트림). key/nonce 가 맞으면 평문 복원.
    return Cipher(key, nonce).decrypt(ct)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("encfile")
    ap.add_argument("--nonce", type=int, default=None, help="알고 있으면 지정 (전수조사 생략)")
    ap.add_argument("--out", default="flag_decrypted.bmp")
    ap.add_argument("--scan-start", type=int, default=0)
    ap.add_argument("--scan-end", type=int, default=1 << 32)
    args = ap.parse_args()

    ct = open(args.encfile, "rb").read()
    body = ct[54:]  # BMP 헤더 54바이트 제외한 픽셀부

    nonce = args.nonce
    if nonce is None:
        print("[*] nonce 전수조사 시작 (순수 파이썬은 느립니다. 대규모는 C 버전 권장)...")
        nonce = recover_nonce_python(body, args.scan_start, args.scan_end)
        if nonce is None:
            print("[!] 범위 내에서 nonce를 찾지 못함")
            sys.exit(1)
    print(f"[+] nonce = {nonce}")

    Vch = []
    for ch in range(3):
        viol, V = find_channel_V(body, nonce, ch)
        Vch.append(V)
        print(f"[+] channel {ch}: V(key[배경]) = {V}  (violations={viol})")

    key = recover_key(body, nonce, Vch)
    print(f"[+] key 복원 완료 (key[:8] = {key[:8]} ...)")

    dec = decrypt(ct, key, nonce)
    open(args.out, "wb").write(dec)

    if dec[:2] == b"BM":
        fsize = struct.unpack("<I", dec[2:6])[0]
        w = struct.unpack("<i", dec[18:22])[0]
        h = struct.unpack("<i", dec[22:26])[0]
        bpp = struct.unpack("<H", dec[28:30])[0]
        print(f"[+] 유효한 BMP: {w}x{h}, {bpp}bpp, size={fsize}")
        print(f"[+] 저장: {args.out}  (이미지를 열어 플래그 확인)")
    else:
        print("[!] BMP 시그니처(BM) 불일치 — nonce/key 재확인 필요")

if __name__ == "__main__":
    main()
