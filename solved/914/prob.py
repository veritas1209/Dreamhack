from Crypto.Util.number import getStrongPrime, bytes_to_long, inverse
from secrets import randbelow
from math import isqrt

def is_sqrt(n):
    return isqrt(n)**2 == n

def check(P):
	x, y = P
	return (a * x**2 + b * y**2 - d * x**2 * y**2 - 1) % p == 0

def add(P, Q):
	assert check(P) and check(Q)
    
	x1, y1 = P
	x2, y2 = Q
	_x = bsqrt * x1 * y2 + y1 * x2 * inverse(1 + d * x1 * x2 * y1 * y2, p)
	_y = (b * y1 * y2 - a * x1 * x2) * inverse(1 - d * x1 * x2 * y1 * y2, p) * inverse(bsqrt, p)

	return (_x % p, _y % p)

def double(P):
	assert check(P)
    
	x, y = P
	_x = 2 * bsqrt * x * y * inverse(1 + d * x**2 * y**2, p)
	_y = (b * y**2 - a * x**2) * inverse(1 - d * x**2 * y**2, p) * inverse(bsqrt, p)

	return (_x % p, _y % p)
    
def double_and_add(n, P):
    assert check(P)
    assert n > 0

    Q = (0, inverse(bsqrt))
    while n > 0:
        if n % 2 == 1:
            Q = add(Q, P)
        P = double(P)
        n //= 2
    return Q

def legendre(a, p):
    return pow(a, (p - 1) // 2, p)

def is_tonelli(n, p):
    return legendre(n, p) == 1

def tonelli(n, p):
    assert legendre(n, p) == 1, "not a square (mod p)"
    
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r

with open('flag', 'rb') as f:
    FLAG = f.read()

p = getStrongPrime(512)
a = randbelow(p)
bsqrt = randbelow(isqrt(p))
b = bsqrt ** 2
d = bytes_to_long(FLAG)

x = randbelow(p)
y2 = ((a * x**2 - 1) * inverse(d * x**2 - b, p)) % p
while not is_tonelli(y2, p):
    x = randbelow(p)
    y2 = ((a * x**2 - 1) * inverse(d * x**2 - b, p)) % p
P1 = (x, tonelli(y2, p))
assert check(P1)

P2 = double(P1)
P3 = double(P2)

print(f"{P1 = }")
print(f"{P2 = }")
print(f"{P3 = }")

"""
result

P1 = (21684180133424657511908369853584326789584407745866503260005237244804501663485673507743999830168738515920475505397147129936455872516435874218934858867286, 9763706949425045696239856203319721634651686079372917598096103959266021015809340290573645001094754815339744526369875908753458477171793951934899015829432213)
P2 = (3865282561441917111097438332833281019701235953095756474399511232727733568725305310302820930535014143646393229192851828528117617926536647780118370128895467, 2915748263224875166581455340510964093183982791887736849301749464166783597624989961203946732747921120506820178248459777623588802298333173585030523625245325)
P3 = (9253221412839934605959466611792221672234892566989578166122978239122939479980612545578690850417393772880978906487067870158689416892921352803249492146065862, 10362305272922186509640051458762453666233283531768323022875900413033956429399167629165847484989496982355965974110192365015911019136199717750618765316280099)
"""