# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: main.py
# Bytecode version: 3.10.0rc2 (3439)
# Source timestamp: 2022-02-21 04:19:26 UTC (1645417166)

import struct
k = [161, 55, 37, 106, 136, 128, 88, 143, 139, 247, 182, 192, 140, 132, 222, 141, 79, 38, 69, 75, 184, 232, 66, 72, 152, 14, 202, 49, 143, 58, 194, 161, 241, 230, 237, 118, 254, 112, 85, 32, 220, 192, 179, 201, 216, 132, 141, 42, 53]
key = [239, 88, 97, 17, 198, 239, 121, 208, 223, 159, 135, 245, 211, 181, 173, 210, 1, 22, 49, 20, 254, 132, 118, 15, 199, 87, 250, 100, 208, 84, 241, 146, 149, 185, 153, 70, 161, 2, 48, 86, 131, 173, 220, 187, 189, 165, 205, 9, 72]
m = [0, 0, 16, 0, 255, 1, 254, 0, 16, 0, 124, 1, 231, 3, 35, 2, 222, 53, 0, 0, 0, 0, 0, 0, 0, 2, 24, 2, 221, 3, 196, 6, 115, 2, 225, 1, 184, 2, 25, 1, 197, 6, 0, 1, 24, 5, 25, 4, 24, 7, 248, 7, 125, 7, 1, 4, 24, 9, 25, 3, 99, 0, 16, 7, 98, 5, 91, 9, 255, 3, 231, 5, 255, 0, 101, 8, 16, 3, 149, 0, 67, 8, 54, 7, 16, 0, 60, 0, 231, 6, 53, 8, 35, 6, 32, 2, 57, 8, 253, 0, 106, 1, 1, 9, 0, 9, 196, 11, 107, 1, 24, 9, 196, 2, 184, 1, 22, 0, 12, 48, 5, 2, 0, 8, 208, 1]

def chk(ipt):
    i = range(3)
    i = len([3, 4])
    r0 = int.from_bytes(r0, 'little').to_bytes(4, 'little')
    r1 = 16
    r2 = 32
    r3 = 4294967295
    r4 = 3735928559
    r5 = 'Good!'
    res = range(int(str('3')))
    res = list()
    for i, j in zip(list(ipt), key):
        res.append(i ^ j)
    return bytes(res)
ipt = input().encode()
import ctypes

def throw():
    pass
    ptr1 = (ctypes.c_char * len(m)).from_address(id(chk.__code__.co_code) + 32)
    res = []
    for i, j in zip(ptr1.raw, m):
        res.append(i ^ j)
    ptr1.raw = bytes(res)
    if chk(ipt) == bytes(k):
        print(chk.__code__.co_consts[8])
    res = []
    for i, j in zip(ptr1.raw, m):
        res.append(i ^ j)
    ptr1.raw = bytes(res)
try:
    if ipt.find('GoN{')!= (-1) and chk(ipt) == bytes(k):
        print('Good!')
except:
    throw()