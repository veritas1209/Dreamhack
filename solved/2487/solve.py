import hashlib
import random
from sympy import GF, nextprime
import time

# Given data
xs = [102705, 206732, 695986, 891078, 224470, 997430, 283570, 938525, 77651, 168414, 38706, 800636, 880647, 461823, 348454, 477999, 758618, 762407, 589050, 903653, 447938, 930082, 143564, 60080, 722903, 703045, 234201, 288616, 132817, 135544, 799768, 229341, 346097, 704249, 471179, 691362, 117218, 577748, 835612, 548825, 920652, 678540, 996474, 455771, 324330, 350032, 786682, 626553, 589602, 963719, 746558, 507100, 555341, 973291, 988630, 644270, 57679, 537931, 303451, 690159, 658410, 722442, 301107, 424105]
ys = [1198300448, 410200986, 2057296503, 1581028415, 599712423, 1118947869, 1484355876, 1558761170, 655180426, 2030816641, 346743026, 1612047891, 731037541, 852024622, 276792981, 887401678, 950513488, 1154009635, 1788788123, 1440076611, 268750750, 207421073, 135324612, 1715449989, 996826523, 1076322692, 1802569271, 1108706914, 1378122, 137864333, 2127029277, 846831626, 334982712, 2014267050, 625475676, 1514123106, 1622245371, 950782692, 1646103475, 207772720, 2145125503, 1661050828, 2137236907, 1294843093, 992959306, 1851364859, 1820151773, 2090874514, 1622471941, 462481343, 588316529, 1746136946, 1917581748, 416930874, 889663975, 1844342989, 1423369582, 1530659676, 1610501657, 1362521034, 299563953, 1604501457, 1831415644, 910264884]
N = 78866437723096861128030630915310359729550372925081150975091742535286746627687614153143948627985008342867316270820290670562550239816143951575506878387954661569985329694660405251976109973977589486078507197146915169268443875396015427646554478573419024909861630446108315893165470622462086831605857951377585131377
e = 65537
c = 63349914049678044274775107936688115757339438854268033701598203631866677417757934563324963288912691761702706032905261947434007458654036237025001927188743966390756201542580118743524175126716747484262774836778714381781206571672090759600897700148473724986483534904194854627129946539277063805091584207671431159921

P = 2**31 - 1
d = 20
n = 64
t = 10

print("=" * 70)
print("RSA CTF Solver - Fast SymPy Version")
print("=" * 70)
print(f"\nPolynomial degree: {d}")
print(f"Total points: {n}")
print(f"Corrupted points: {t}")
print(f"Need {d+1} correct points to interpolate\n")

# Create finite field
K = GF(P)

def fast_lagrange_interpolation(points, P):
    """Fast Lagrange interpolation using basic arithmetic"""
    n = len(points)
    coeffs = [0] * n
    
    for i in range(n):
        xi, yi = points[i]
        # Compute Lagrange basis
        num = [1]
        denom = 1
        
        for j in range(n):
            if i != j:
                xj = points[j][0]
                # num *= (x - xj)
                new_num = [0] * (len(num) + 1)
                for k in range(len(num)):
                    new_num[k] = (new_num[k] - num[k] * xj) % P
                    new_num[k+1] = (new_num[k+1] + num[k]) % P
                num = new_num
                denom = (denom * (xi - xj)) % P
        
        # Multiply by yi / denom
        inv = pow(denom, -1, P)
        factor = (yi * inv) % P
        
        for k in range(len(num)):
            coeffs[k] = (coeffs[k] + num[k] * factor) % P
    
    return coeffs[:d+1]

def eval_poly(coeffs, x, P):
    """Evaluate polynomial at x"""
    result = 0
    x_pow = 1
    for c in coeffs:
        result = (result + c * x_pow) % P
        x_pow = (x_pow * x) % P
    return result

def verify_polynomial(coeffs, xs, ys, P):
    """Check how many points match"""
    matches = 0
    for i in range(len(xs)):
        if eval_poly(coeffs, xs[i], P) == ys[i]:
            matches += 1
    return matches

def test_N_generation(coeffs):
    """Test if coefficients generate correct N"""
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

print("Starting search (Fast Lagrange interpolation)...")
print("Progress shown every 100 attempts\n")

best_matches = 0
max_attempts = 50000
start_time = time.time()

for attempt in range(max_attempts):
    # Progress every 100 attempts
    if attempt % 100 == 0 and attempt > 0:
        elapsed = time.time() - start_time
        rate = attempt / elapsed
        print(f"[{attempt:6d}/{max_attempts}] Best: {best_matches}/64 | {rate:.0f} att/sec | {elapsed:.1f}s elapsed", end='\r')
    
    # Random subset
    indices = random.sample(range(n), d + 1)
    points = [(xs[i], ys[i]) for i in indices]
    
    try:
        # Fast interpolation
        coeffs = fast_lagrange_interpolation(points, P)
        
        # Verify
        matches = verify_polynomial(coeffs, xs, ys, P)
        
        if matches > best_matches:
            best_matches = matches
            print(f"\n[Attempt {attempt:6d}] NEW BEST: {matches}/{n} points match!" + " " * 30)
            
            if matches >= n - t:  # 54+ matches
                print(f"  → Testing N generation...")
                is_correct, p, q = test_N_generation(coeffs)
                
                if is_correct:
                    print("\n" + "=" * 70)
                    print("✓✓✓ SUCCESS! ✓✓✓")
                    print("=" * 70)
                    
                    # Decrypt
                    phi = (p - 1) * (q - 1)
                    d_priv = pow(e, -1, phi)
                    m = pow(c, d_priv, N)
                    
                    flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                    
                    print(f"\n🚩 FLAG: {flag_bytes.decode()}")
                    print("=" * 70)
                    exit(0)
                else:
                    print(f"  → N doesn't match, continuing...")
        
        # Detailed progress every 5000
        if attempt % 5000 == 0 and attempt > 0:
            elapsed = time.time() - start_time
            rate = attempt / elapsed
            eta = (max_attempts - attempt) / rate if rate > 0 else 0
            print(f"\n{'='*70}")
            print(f"Progress: {attempt}/{max_attempts} | Best: {best_matches}/64")
            print(f"Speed: {rate:.0f} att/sec | ETA: {eta/60:.1f} min")
            print(f"{'='*70}\n")
            
    except Exception as e:
        continue

elapsed = time.time() - start_time
print(f"\n\n{'='*70}")
print(f"Search completed in {elapsed:.1f} seconds")
print(f"Best match: {best_matches}/{n} points")
print(f"{'='*70}")
print("\nTips:")
print("1. Run again with different random seed")
print("2. The correct polynomial should match exactly 54 points")