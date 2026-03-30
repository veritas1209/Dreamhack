#!/usr/bin/env python3
import random
from math import gcd

flag = "DH{fake}"
key = 73

while True:
    x = random.randint(1000, 9999)
    y = random.randint(1000, 9999)
    if gcd(x, y) == 1:
        break

a = key * x
b = key * y

enc = [ord(c) ^ key for c in flag]

with open("output.txt", "w", encoding="utf-8") as f:
    f.write("[Donghyeok's Note]\n\n")
    f.write("I hid your USB.\n")
    f.write("If you want it back, decode this.\n\n")
    f.write(f"a = {a}\n")
    f.write(f"b = {b}\n")
    f.write(f"enc = {enc}\n")