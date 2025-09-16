from Crypto.Util.number import *
from secret import flag, r, k3_r  

assert len(flag) % 3 == 0

t = len(flag) // 3
m1, m2, m3 = flag[:t], flag[t:2*t], flag[2*t:]
x, y, z = map(bytes_to_long, (m1, m2, m3))

k1 = '12815b6189456f7eae8e16eab976bdd2868065e0a0417a1c95fcf75bc1fd7ebf9388b9e3445262b1bd58798a3a2d9d2832cab2f21f7104e3688afb01467ae1'
k2 = '3852a5eaea74c2e07c15a78c5ce6d5778a58d5998eee0421ade2bddf8c527d7c9d85e03e77c3ece257a64806cb11ff168e4e7e4a69140063d8c96c483f4604'
k3_l = 'fc6851611af77ed3b241816041950c9464899c370edb7131913ddb06329ecd85'

k3 = k3_l + k3_r

f = lambda a,b,k: (a*a+1)*(b*b+1) - 2*(a-b)*(a*b-1) == 4*(int(k, r) + a*b)

assert f(x, y, k1)
assert f(y, z, k2)
assert f(z, x, k3)
