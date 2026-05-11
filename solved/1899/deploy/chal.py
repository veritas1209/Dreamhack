from Crypto.Util.number import getPrime
import secrets

p, q, r, s = getPrime(256), getPrime(256), getPrime(256), getPrime(256)
e = 521

def get_d(p, q):
    return pow(e, -1, (p - 1) * (q - 1))
n1, n2, n3, n4 = p * q, q * r, r * s, s * p
d1, d2, d3, d4 = get_d(p, q), get_d(q, r), get_d(r, s), get_d(s, p)

def enc(v):
    v = pow(v, e, n1)
    v = pow(v, e, n2)
    v = pow(v, e, n3)
    v = pow(v, e, n4)
    return v

def dec(v):
    v = pow(v, d4, n4)
    v = pow(v, d3, n3)
    v = pow(v, d2, n2)
    v = pow(v, d1, n1)
    return v

while True:
    sel = int(input("> ").strip())
    if sel == 1:
        val = int(input("pt > "))
        print(f"{enc(val) = }")
    elif sel == 2:
        val = int(input("ct > "))
        print(f"{dec(val) = }")
    elif sel == 3:
        secret = secrets.randbelow(n1)
        print(f"{enc(secret) = }")
        val = int(input("secret > "))
        if val == secret:
            with open("flag", "r") as f:
                print(f.read())
        exit(0)