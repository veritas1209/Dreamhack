from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from math import prod
import sys
import hashlib
import random
import string

sys.set_int_max_str_digits(0)

stages = [8, 12, 16, 24, 32]
flags = []

for num, bits in enumerate(stages, 1):
    n = 50
    rand = ""
    for i in range(n):
        rand += str(random.choice(string.ascii_uppercase))
    
    data = rand

    obj = hashlib.md5()
    obj.update(data.encode())
    value = obj.hexdigest()

    ps = [getPrime(bits) for _ in range(444)]
    n = prod(ps)
    e = 65537
    
    flag = value
    m = bytes_to_long(flag.encode())
    c = pow(m, e, n)
    
    flags.append(flag)
    
    print(f"stage {num}!")
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"c = {c}")
    print()
    
    ans = input("dec : ")
    
    if ans != flag:
        print("nope!")
        sys.exit(1)
    
    print("Correct!")
    print()

print("Congrats!")
print(f"Here is your flag! {FLAG}")