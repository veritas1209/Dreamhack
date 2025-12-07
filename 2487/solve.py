import hashlib
import random
from sympy import symbols, Poly, GF, nextprime
from sympy.polys.polyfuncs import interpolate

# Given data
xs = [102705, 206732, 695986, 891078, 224470, 997430, 283570, 938525, 77651, 168414, 38706, 800636, 880647, 461823, 348454, 477999, 758618, 762407, 589050, 903653, 447938, 930082, 143564, 60080, 722903, 703045, 234201, 288616, 132817, 135544, 799768, 229341, 346097, 704249, 471179, 691362, 117218, 577748, 835612, 548825, 920652, 678540, 996474, 455771, 324330, 350032, 786682, 626553, 589602, 963719, 746558, 507100, 555341, 973291, 988630, 644270, 57679, 537931, 303451, 690159, 658410, 722442, 301107, 424105]
ys = [1198300448, 410200986, 2057296503, 1581028415, 599712423, 1118947869, 1484355876, 1558761170, 655180426, 2030816641, 346743026, 1612047891, 731037541, 852024622, 276792981, 887401678, 950513488, 1154009635, 1788788123, 1440076611, 268750750, 207421073, 135324612, 1715449989, 996826523, 1076322692, 1802569271, 1108706914, 1378122, 137864333, 2127029277, 846831626, 334982712, 2014267050, 625475676, 1514123106, 1622245371, 950782692, 1646103475, 207772720, 2145125503, 1661050828, 2137236907, 1294843093, 992959306, 1851364859, 1820151773, 2090874514, 1622471941, 462481343, 588316529, 1746136946, 1917581748, 416930874, 889663975, 1844342989, 1423369582, 1530659676, 1610501657, 1362521034, 299563953, 1604501457, 1831415644, 910264884]
N = 78866437723096861128030630915310359729550372925081150975091742535286746627687614153143948627985008342867316270820290670562550239816143951575506878387954661569985329694660405251976109973977589486078507197146915169268443875396015427646554478573419024909861630446108315893165470622462086831605857951377585131377
e = 65537
c = 63349914049678044274775107936688115757339438854268033701598203631866677417757934563324963288912691761702706032905261947434007458654036237025001927188743966390756201542580118743524175126716747484262774836778714381781206571672090759600897700148473724986483534904194854627129946539277063805091584207671431159921

P = 2**31 - 1  # Prime modulus
d = 20  # polynomial degree
n = 64  # number of points
t = 10  # number of corrupted points

print("=" * 70)
print("RSA CTF Solver - SymPy Version")
print("=" * 70)
print(f"\nPolynomial degree: {d}")
print(f"Total points: {n}")
print(f"Corrupted points: {t}")
print(f"Need {d+1} correct points to interpolate\n")

# Create finite field
K = GF(P)
x = symbols('x')

def interpolate_poly(points):
    """Interpolate polynomial using sympy over finite field"""
    # Convert points to list of tuples
    point_list = [(K(xi), K(yi)) for xi, yi in points]
    
    # Use sympy's interpolate
    poly = interpolate(point_list, x)
    
    # Convert to Poly object in finite field
    poly_ff = Poly(poly, x, domain=K)
    
    return poly_ff

def eval_poly_at(poly, x_val):
    """Evaluate polynomial at a point"""
    result = poly.eval(K(x_val))
    return int(result)

def verify_polynomial(poly, xs, ys):
    """Check how many points match the polynomial"""
    matches = 0
    matched_indices = []
    for i in range(len(xs)):
        pred = eval_poly_at(poly, xs[i])
        if pred == ys[i]:
            matches += 1
            matched_indices.append(i)
    return matches, matched_indices

def get_coefficients(poly):
    """Extract coefficients as list of integers"""
    coeffs = []
    for i in range(d + 1):
        coeff = poly.nth(i)
        if coeff is None:
            coeffs.append(0)
        else:
            coeffs.append(int(coeff))
    return coeffs

def test_N_generation(coeffs):
    """Test if coefficients generate the correct N"""
    packed = b"".join(int(c).to_bytes(4, "big") for c in coeffs)
    seed_int = int.from_bytes(hashlib.sha256(packed).digest(), "big")
    random.seed(seed_int)
    
    BITS = 512
    mk = lambda: (random.getrandbits(BITS) | (1<<(BITS-1)) | 1)
    
    p = nextprime(mk())
    q = nextprime(mk())
    while p == q:
        q = nextprime(mk())
    
    return p * q == N, p, q

print("Starting search for correct polynomial...\n")

best_matches = 0
attempts_since_improvement = 0
max_attempts = 50000

for attempt in range(max_attempts):
    # Randomly select d+1 points
    indices = random.sample(range(n), d + 1)
    points = [(xs[i], ys[i]) for i in indices]
    
    try:
        # Interpolate polynomial
        poly = interpolate_poly(points)
        
        # Verify how many points it matches
        matches, matched_indices = verify_polynomial(poly, xs, ys)
        
        if matches > best_matches:
            best_matches = matches
            attempts_since_improvement = 0
            print(f"Attempt {attempt:6d}: New best - {matches}/{n} points match")
            
            # If we have a very good match, test if it produces correct N
            if matches >= n - t:  # At least 54 matches
                print(f"  → Testing N generation...")
                coeffs = get_coefficients(poly)
                is_correct, p, q = test_N_generation(coeffs)
                
                if is_correct:
                    print("\n" + "=" * 70)
                    print("✓✓✓ SUCCESS! Found the correct polynomial! ✓✓✓")
                    print("=" * 70)
                    print(f"\nMatches: {matches}/{n} points")
                    print(f"Matched indices: {sorted(matched_indices)[:10]}...")
                    
                    print("\nCoefficients (first 5):")
                    for i in range(min(5, len(coeffs))):
                        print(f"  c[{i}] = {coeffs[i]}")
                    
                    print(f"\nRSA primes found:")
                    print(f"  p ({p.bit_length()} bits)")
                    print(f"  q ({q.bit_length()} bits)")
                    
                    # Decrypt the flag
                    phi = (p - 1) * (q - 1)
                    d_priv = pow(e, -1, phi)
                    m = pow(c, d_priv, N)
                    
                    flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                    
                    print(f"\n{'='*70}")
                    print(f"🚩 FLAG: {flag_bytes.decode()}")
                    print("=" * 70)
                    exit(0)
                else:
                    print(f"  → N doesn't match (continuing search...)")
        else:
            attempts_since_improvement += 1
        
        # Progress updates
        if attempt % 2000 == 0 and attempt > 0:
            print(f"\n[Progress] {attempt}/{max_attempts} attempts")
            print(f"[Progress] Best match: {best_matches}/{n} points")
            print(f"[Progress] Attempts since improvement: {attempts_since_improvement}\n")
            
        # If stuck, maybe print encouragement
        if attempts_since_improvement > 10000 and attempts_since_improvement % 5000 == 0:
            print(f"[Info] Still searching... best is {best_matches}/{n} matches\n")
            
    except Exception as e:
        # Skip this combination if interpolation fails
        continue

print("\n" + "=" * 70)
print("❌ Search completed without finding solution")
print("=" * 70)
print(f"Best match achieved: {best_matches}/{n} points")
print("\nSuggestions:")
print("1. Run the script again (different random seed)")
print("2. Increase max_attempts")
print("3. The polynomial might need exactly 54 correct points")