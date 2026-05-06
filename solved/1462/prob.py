#!/usr/bin/env python3
import os
from cipher import SPN

with open("flag", "rb") as f:
    flag = f.read()
with open("key", "rb") as f:
    key = f.read()

spn = SPN(key)

with open('data', 'wb') as f:
    for i in range(20000):
        pt = os.urandom(8)
        ct = spn.encrypt(pt)
        check = spn.decrypt(ct)
        assert check == pt
        f.write(pt)
        f.write(ct)

with open('enc_flag', 'wb') as f:
    enc_flag = spn.encrypt(flag)
    f.write(enc_flag)
