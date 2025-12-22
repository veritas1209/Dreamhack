# Fastest method: Eliminate k2 algebraically
# Copy to https://sagecell.sagemath.org/

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

F = GF(p)
P256 = EllipticCurve(F, [a, b])

data = [
    (27714350255388021111232531170591641212949833102971307193980499863801255688154, 46284378768605864622170543556599427573485337746700029009471119922484581943469, 60647595877197062890203383385574231236668829536178956561727275653380079298295, 82566598899232397169905495928712993370226968781169912617729109115055982292654),
    (66685775596410543041483496379768749621617386544202895231662933335573761066984, 24293856516706702970952028821050887716345151887846419189741989582569242079317, 5544069395933034652167871260816830292182111986234313654127458493687089162323, 35676905401837729400864551915248562488714964484188718193693644401814797799759),
]

print("=== Elimination Method ===\n")

a1, b1, c1, d1 = data[0]
a2, b2, c2, d2 = data[1]

print("Strategy: Eliminate k2 to get polynomial in k1 only\n")

# From the two equations:
# poly1: 4*(px1^3 + a*px1 + b)*(qx1 + 2*px1) - (3*px1^2 + a)^2 = 0
# poly2: 4*(px2^3 + a*px2 + b)*(qx2 + 2*px2) - (3*px2^2 + a)^2 = 0

# Where px1 = a1*k1 + b1, qx1 = c1*k2 + d1
#       px2 = a2*k1 + b2, qx2 = c2*k2 + d2

# We can solve for k2 from the first equation:
# qx1 = c1*k2 + d1
# From doubling formula, qx1 is determined by px1
# So k2 = (qx1 - d1) / c1

# Similarly from second equation:
# k2 = (qx2 - d2) / c2

# These must be equal!
# (qx1 - d1) / c1 = (qx2 - d2) / c2
# c2*(qx1 - d1) = c1*(qx2 - d2)

print("Using elimination to create univariate polynomial in k1...\n")

R.<k1> = PolynomialRing(F)

# For a given k1, compute qx1 and qx2 using the doubling formula
# qx = lambda^2 - 2*px where lambda = (3*px^2 + a) / (2*y)
# 
# Squaring: 4*y^2*qx = (3*px^2 + a)^2 - 8*px*y^2
# 4*y^2*(qx + 2*px) = (3*px^2 + a)^2
# Since y^2 = px^3 + a*px + b:
# 4*(px^3 + a*px + b)*(qx + 2*px) = (3*px^2 + a)^2

# So: qx = [(3*px^2 + a)^2] / [4*(px^3 + a*px + b)] - 2*px

px1 = a1*k1 + b1
px2 = a2*k1 + b2

# Compute qx1 and qx2
numerator1 = (3*px1^2 + a)^2
denominator1 = 4*(px1^3 + a*px1 + b)
# qx1 = numerator1 / denominator1 - 2*px1

numerator2 = (3*px2^2 + a)^2
denominator2 = 4*(px2^3 + a*px2 + b)
# qx2 = numerator2 / denominator2 - 2*px2

# From k2 = (qx1 - d1) / c1 = (qx2 - d2) / c2
# c2 * (qx1 - d1) = c1 * (qx2 - d2)

# Substitute qx expressions:
# c2 * (numerator1/denominator1 - 2*px1 - d1) = c1 * (numerator2/denominator2 - 2*px2 - d2)

# Clear denominators:
# c2 * denominator2 * (numerator1 - 2*px1*denominator1 - d1*denominator1) = 
# c1 * denominator1 * (numerator2 - 2*px2*denominator2 - d2*denominator2)

lhs = c2 * denominator2 * (numerator1 - 2*px1*denominator1 - d1*denominator1)
rhs = c1 * denominator1 * (numerator2 - 2*px2*denominator2 - d2*denominator2)

equation = lhs - rhs

print(f"Created polynomial of degree {equation.degree()} in k1")
print("Finding roots...\n")

# This polynomial should have k1 as a root
roots = equation.roots()

print(f"Found {len(roots)} potential values for k1\n")

for k1_val, multiplicity in roots:
    print(f"Testing k1 = {k1_val}...")
    
    # Compute corresponding k2
    px_test = F(a1 * k1_val + b1)
    
    # Check if this gives a valid curve point
    y_sq = px_test^3 + a*px_test + b
    
    if not y_sq.is_square():
        print("  Invalid (not a curve point)")
        continue
    
    y_test = y_sq.sqrt()
    
    # Try both y values
    for y_val in [y_test, -y_test]:
        try:
            P = P256.point((px_test, y_val))
            Q = P + P
            qx = Q[0]
            
            # Compute k2
            k2_val = (qx - d1) / F(c1)
            
            # Verify with second equation
            px2_test = F(a2 * k1_val + b2)
            y_sq2 = px2_test^3 + a*px2_test + b
            
            if not y_sq2.is_square():
                continue
            
            y2_test = y_sq2.sqrt()
            
            for y2_val in [y2_test, -y2_test]:
                try:
                    P2 = P256.point((px2_test, y2_val))
                    Q2 = P2 + P2
                    qx2 = Q2[0]
                    
                    qx2_expected = F(c2 * k2_val + d2)
                    
                    if qx2 == qx2_expected:
                        print("\n" + "="*60)
                        print("✓✓✓ SOLUTION FOUND! ✓✓✓")
                        print("="*60)
                        print(f"\nkey1 = {Integer(k1_val)}")
                        print(f"key2 = {Integer(k2_val)}")
                        
                        key = Integer(k1_val) ^^ Integer(k2_val)
                        flag = f"DH{{{key:064x}}}"
                        print(f"\n🚩 Flag: {flag}")
                        print("="*60)
                        
                        import sys
                        sys.exit(0)
                except:
                    pass
        except:
            pass
    
    print("  Verification failed")

print("\nNo valid solution found among the roots.")