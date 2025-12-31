from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes 
from secret import flag 
import os, secrets, signal 
 
p, q = getPrime(512), getPrime(512) 
n = p ** 2 * q 

while True: 
    g = secrets.randbelow(n-2) + 2
    if pow(g, (p - 1), p ** 2) != 1: 
        if pow(g, (p - 1), p) == 1: 
            break 

li = [bytes_to_long(os.urandom(32)) for _ in range(1000)]
h = pow(g, n, n) 
m1 = bytes_to_long(os.urandom(32))
m2 = m1 + secrets.randbelow(1 << 28)
r = secrets.choice(li)
c1 = (pow(g, m1, n) * pow(h, r, n)) % n 

signal.alarm(10)

while True:
    chs = int(input("> "))
    if chs == 1:
        print(f"{n = }")
        print(f"{g = }")
        print(f"{c1 = }")
    elif chs == 2:
        r_ = secrets.choice(li)
        c2 = (pow(g, m2, n) * pow(h, r_, n)) % n 
        print(f"{c2 = }")
        if r_ == r:
            print("Hmm..?")
    elif chs == 3:
        ans = int(input("answer? > "))
        if ans == m2 - m1:
            print("Gorgeous!")
            print(flag)
        else:
            print("Ewwwwww :(")
            break
