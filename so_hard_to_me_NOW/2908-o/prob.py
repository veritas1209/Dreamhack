from Crypto.Util.number import bytes_to_long as bt

p = 65600183790238227313760556956092111650257433601025206897856652615182760244463
m = 15
u = 11
v = 13
deg = 3
la = 4
lb = 5

def h(x, n):
    a = 2
    b = x
    if n == 0:
        return a
    if n == 1:
        return b
    for i in range(2, n + 1):
        a, b = b, (x * b - a) % p
    return b

def g(f):
    assert len(f) == 2 * m
    a = bt(f[:m])
    b = bt(f[m:])
    x = a * pow(b, -1, p) % p
    x = (x + pow(x, -1, p)) % p
    return h(x, u), h(x, v)

def o(f, x, n):
    s = [x]
    for i in range(n - 1):
        x = f(x)
        s.append(x)
    return s
