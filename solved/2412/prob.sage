from Crypto.Util.number import bytes_to_long
from random import sample

flag = b'KoS{--[REDACTED]--}'

def circle(x, r):
    return R(r^2 - x^2)^0.5

flag = bytes_to_long(flag)
assert len(str(flag)) == 116

R = RealField(4 * len(str(flag)))
x = R(flag * 10^(-len(str(flag))))
y = x

for r in range(20, 101):
    assert r - 1 / x > 0
    x = circle(x, R(r - 1 / x))

ans = f'{x:f}'
for i in sample(range(len(ans)), 12):
    ans = ans[:i] + '?' + ans[i+1:]
print(ans)