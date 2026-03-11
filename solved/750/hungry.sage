from Crypto.Util.number import *

p = (๑ᵔ⤙ᵔ๑)     # I ate your p for breakfast!
a = (๑ᵔ⤙ᵔ๑)     # I ate your a for lunch!
b = (๑ᵔ⤙ᵔ๑)     # I ate your b for snack!
d = (๑ᵔ⤙ᵔ๑)     # I ate your d for dinner!
FLAG = (๑ᵔ⤙ᵔ๑)  # I ate your flag for midnight snack!

assert len(FLAG) == 22 # Big hint!
assert isPrime(p)

Zp = IntegerModRing(p)
a = Zp(a)
b = Zp(b)
d = Zp(d)

def good_sqrt(n):
	try:
		int(n)
		return True
	except:
		return False

bsqrt = b.sqrt()
assert good_sqrt(bsqrt)

def gen_G():
	x = Zp.random_element()
	y = ((a * x^2 - 1) / (d * x^2 - b)).sqrt()
	if good_sqrt(y):
		return (x, y)
	return gen_G()

def check(P):
	x, y = P
	return a * x^2 + b * y^2 == d * x^2 * y^2 + 1

def add(P, Q):
	assert check(P) and check(Q)
	x1, y1 = P
	x2, y2 = Q
	x3 = bsqrt * (x1 * y2 + y1 * x2) / (1 + d * x1 * x2 * y1 * y2)
	y3 = (b * y1 * y2 - a * x1 * x2) / (1 - d * x1 * x2 * y1 * y2) / bsqrt

	return (x3, y3)

def mul(G, m):
	P = (0, 1 / bsqrt)

	for i in range(300):
		if m & (1 << i):
			P = add(P, powG[i])
	assert check(P)
	return P

G = gen_G()
assert check(G)

powG = []
T = G
for i in range(300):
	powG.append(T)
	T = add(T, T)

print(powG[-3:]) # I tried to eat all, but couldn't eat last 3 of them!
print(mul(G, bytes_to_long(FLAG.encode())))
print(mul(G, p)) # I got a bellyache.....

