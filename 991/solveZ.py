# 순수 Python + sympy로 구현 - Windows에서 바로 실행 가능!
# pip install sympy

# 주어진 값들
N = 21605078068881498782819048171894829027309073706899700368320898306585692569989037051800262879920595007282368584236406267684936418879719173323944786406385213715891905152177564963981315245140222449203077248953976257742155758441359533536709300299774032366657788036496959849898683764666932427683272724861241129038445118071370266452729059517082678438816843970169034272974470329661409192276205785270099230147636829235755430320319707389119023770204763073024720205484886273151609846161749754508683921665139614833651876830883334247742161865123555983809999642252319169052590465069995573253351532504852901266961578272338670348367
e = 12323
c1 = 20089218479858612694242629777663519453555438534104822578338254908252825485555168585607069874403023659158601900966904607461556061179363779646899281413405668204871774675457671679099932808045201194210099049024788880294050051491419229120556495222935100682226453507983989606251414763340638571480730711098325171826346902088270238368040496910306420248481742415271335021113839576595773102490407287059707113189779830753044627646480909263574359295289454216148015482931568652052152387684496751707446168856385928092263914090401410627266896526096381247889671896046414514726970393582242180759850215770998243593699056707258065976721
c2 = 14236892148098943164337721411692974730163960547674907615022561931081984144229688171308450922544422961947426528739391762153632741583812585497948857606734539972523531926832301391236401056088640551645968433318349696980756200528910118847311480716708709013429456196969580146807420590558344526274313594042078868372704483528552650368559605162179909839280262676459977669829718309859007620479317684014569952158458423989126993861240170358147782735447826070828305061331148105071764701997542648582064971479024870758180153911358592632223377041090010869291669220105455258397696022064995487923850969816982093551773993650215106923790

# 상수 계산
prefix = b"My last flag is "
suffix = b" is secret"
flag_len = 222
suffix_len = len(suffix)

a = int.from_bytes(prefix, 'big') * (256 ** flag_len)
b = 256 ** suffix_len
c = int.from_bytes(suffix, 'big')

print(f"a = {a}")
print(f"b = {b}")
print(f"c = {c}")
print()

# mod N에서 다항식 연산을 위한 클래스
class PolyModN:
    def __init__(self, coeffs, N):
        # coeffs = [a0, a1, a2, ...] represents a0 + a1*X + a2*X^2 + ...
        self.coeffs = [x % N for x in coeffs]
        self.N = N
        self._normalize()
    
    def _normalize(self):
        # 앞쪽의 0 계수 제거
        while len(self.coeffs) > 1 and self.coeffs[-1] == 0:
            self.coeffs.pop()
    
    def degree(self):
        return len(self.coeffs) - 1
    
    def __mod__(self, other):
        # 다항식 나눗셈의 나머지
        if other.degree() == 0 and other.coeffs[0] == 0:
            raise ValueError("Division by zero polynomial")
        
        dividend = self.coeffs[:]
        divisor = other.coeffs
        
        while len(dividend) >= len(divisor) and dividend:
            # 최고차 계수로 나누기
            coef = (dividend[-1] * pow(divisor[-1], -1, self.N)) % self.N
            deg_diff = len(dividend) - len(divisor)
            
            # 빼기
            for i in range(len(divisor)):
                dividend[deg_diff + i] = (dividend[deg_diff + i] - coef * divisor[i]) % self.N
            
            dividend.pop()
        
        return PolyModN(dividend if dividend else [0], self.N)
    
    def __eq__(self, other):
        return self.coeffs == other.coeffs
    
    def monic(self):
        # 최고차 계수를 1로 만들기
        if self.coeffs[-1] == 0:
            return self
        leading = self.coeffs[-1]
        inv_leading = pow(leading, -1, self.N)
        new_coeffs = [(c * inv_leading) % self.N for c in self.coeffs]
        return PolyModN(new_coeffs, self.N)

def poly_gcd(f1, f2):
    """유클리드 호제법으로 GCD 계산"""
    while not (f2.degree() == 0 and f2.coeffs[0] == 0):
        f1, f2 = f2, f1 % f2
    return f1.monic()

# f1(X) = X^e - c1
f1_coeffs = [(-c1) % N] + [0] * (e - 1) + [1]
f1 = PolyModN(f1_coeffs, N)

# f2(X) = (b*X - b*a + c)^e - c2를 전개
# 이진 거듭제곱으로 계산
def poly_power(base_coeffs, exp, N):
    """(base)^exp mod N을 계산"""
    result = [1]  # 1로 시작
    base = base_coeffs[:]
    
    while exp > 0:
        if exp & 1:
            result = poly_mult(result, base, N)
        base = poly_mult(base, base, N)
        exp >>= 1
    
    return result

def poly_mult(p1, p2, N):
    """두 다항식의 곱셈"""
    result = [0] * (len(p1) + len(p2) - 1)
    for i in range(len(p1)):
        for j in range(len(p2)):
            result[i + j] = (result[i + j] + p1[i] * p2[j]) % N
    return result

print("f2 계산 중... (시간이 좀 걸립니다)")
# (b*X - b*a + c)
linear = [(-b * a + c) % N, b % N]
f2_coeffs = poly_power(linear, e, N)
f2_coeffs[0] = (f2_coeffs[0] - c2) % N
f2 = PolyModN(f2_coeffs, N)

print(f"f1 차수: {f1.degree()}")
print(f"f2 차수: {f2.degree()}")
print()

print("GCD 계산 중...")
g = poly_gcd(f1, f2)
print(f"GCD 차수: {g.degree()}")

if g.degree() == 1:
    # g = X - m1 형태
    # g.coeffs = [g0, g1]이면 g0 + g1*X
    # monic이므로 g1 = 1, 따라서 X = -g0
    m1 = (-g.coeffs[0]) % N
    
    print(f"\n✓ m1 복구 성공!")
    print(f"m1 = {m1}")
    print()
    
    # FLAG 추출
    x = (m1 - a) % N
    
    # 바이트로 변환
    flag_bytes = x.to_bytes(flag_len, 'big')
    flag = flag_bytes.decode('ascii', errors='ignore')
    
    print(f"🚩 FLAG: {flag}")
    print()
    
    # 검증
    m2_recovered = (b * m1 - b * a + c) % N
    print(f"검증:")
    print(f"c1 == m1^e mod N: {pow(m1, e, N) == c1}")
    print(f"c2 == m2^e mod N: {pow(m2_recovered, e, N) == c2}")
else:
    print(f"❌ GCD의 차수가 {g.degree()}입니다. 공격 실패.")