#!/usr/bin/env python3
"""
Trepidation (DreamHack, reversing) — solver

핵심 아이디어
-------------
Go + C++(cgo VM) + Rust 가 섞인 난독화 바이너리지만, 최종 검증은 Go 함수
`main.fullBlockCheck` 로 환원된다. 이 함수는 64바이트 입력을 16개의 32-bit
little-endian dword 로 보고, 고정 배열 K/M/T 와 상태값(state)을 체이닝하며
각 결과를 고정 Target[i] 와 비교한다. 연산이 전부 가역(rol/xor/add)이라
Target 에서 거꾸로 입력 dword 를 복원할 수 있다.

복원된 64바이트는 ASCII 16진 문자열이며, 이를 DH{...} 로 감싼 것이 플래그다.
(바이너리에 직접 넣으면 "OK" 출력)

forward(검증) 로직 (index i, in[i]=입력 dword, state=직전 결과):
    a    = rol32(K[i] ^ in[i], T[i] & 31)
    a    = (a + M[i]) & 0xffffffff
    b    = (i*0x9e37) ^ a
    const= (M[i] & 0xffff) | (((i+1)*0x1021) << 16)
    r9   = const ^ b
    s    = rol32(state ^ r9, ((5*i+7)&31)+1)
    bb   = rol32(i ^ 0x9e3779b9, ((3*i)&31)+1)
    out  = bb ^ s
    require out == Target[i]   ;   state_next = out
"""

import struct

MASK = 0xffffffff


def rol32(x, r):
    r &= 31
    x &= MASK
    if r == 0:
        return x
    return ((x << r) | (x >> (32 - r))) & MASK


def ror32(x, r):
    return rol32(x, (32 - (r & 31)) & 31)


# --- fullBlockCheck 에서 추출한 고정 상수들 -------------------------------
# K, M, Target : movabs 로 적재된 8개의 qword를 little-endian dword 16개로 분해
K = [0xa341316c, 0xc8013ea4, 0xad90777d, 0x7e95761e,
     0x4cf5ad43, 0x8b5a1d2b, 0x9e3779b9, 0x3c6ef372,
     0xdaa66d2b, 0x78dde6e4, 0x1715609d, 0xb54cda56,
     0x5384540f, 0xf1bbcdc8, 0x8ff34781, 0x2e2ac13a]

M = [0x13579bdf, 0x2468ace0, 0x0f1e2d3c, 0x4b5a6978,
     0x89abcdef, 0x10213243, 0x55667788, 0x99aabbcc,
     0xdeadbeef, 0x31415926, 0x27182818, 0xfeedface,
     0xc001d00d, 0xabad1dea, 0x0badf00d, 0x600dcafe]

TARGET = [0x9769ab1d, 0x4d08a686, 0xfaae78fe, 0xff5727e3,
          0x3858f6ec, 0x90e0bd0c, 0x01402014, 0xe59100ce,
          0xa43c746b, 0x1f38cec7, 0x4815fe03, 0x06d61c86,
          0xc5c138dc, 0xdbe96125, 0x70f92bba, 0x5021c295]

# 회전량 배열 T : rodata 0x5bb978 에서 추출 (값들의 &31)
T = [5, 11, 3, 17, 29, 7, 13, 19, 23, 31, 9, 15, 21, 27, 25, 1]

STATE0 = 0x1f123bb5


def forward(i, ini, state):
    """검증 로직 그대로 재현 → out 값 반환 (디버그/검증용)"""
    a = rol32(K[i] ^ ini, T[i] & 31)
    a = (a + M[i]) & MASK
    b = ((i * 0x9e37) & MASK) ^ a
    const = (M[i] & 0xffff) | ((((i + 1) * 0x1021) << 16) & MASK)
    r9 = const ^ b
    s = rol32(state ^ r9, ((5 * i + 7) & 31) + 1)
    bb = rol32((i ^ 0x9e3779b9) & MASK, ((3 * i) & 31) + 1)
    return bb ^ s


def invert(i, state):
    """out == Target[i] 라는 조건에서 입력 dword in[i] 를 역산"""
    bb = rol32((i ^ 0x9e3779b9) & MASK, ((3 * i) & 31) + 1)
    s = ror32(TARGET[i] ^ bb, ((5 * i + 7) & 31) + 1)   # = state ^ r9
    r9 = state ^ s
    const = (M[i] & 0xffff) | ((((i + 1) * 0x1021) << 16) & MASK)
    b = r9 ^ const
    a = ((i * 0x9e37) & MASK) ^ b
    a = (a - M[i]) & MASK
    ini = K[i] ^ ror32(a, T[i] & 31)
    return ini & MASK


def solve():
    state = STATE0
    block = []
    for i in range(16):
        ini = invert(i, state)
        block.append(ini)
        assert forward(i, ini, state) == TARGET[i], f"verify failed at i={i}"
        state = TARGET[i]
    raw = b"".join(struct.pack("<I", x) for x in block)   # 64 ASCII bytes
    inner = raw.decode()
    return f"DH{{{inner}}}"


if __name__ == "__main__":
    flag = solve()
    print("[+] all 16 dwords verified against Target")
    print("[+] FLAG:", flag)
