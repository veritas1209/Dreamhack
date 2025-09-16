from Crypto.Util.number import *
import itertools

# Given values
k1 = '12815b6189456f7eae8e16eab976bdd2868065e0a0417a1c95fcf75bc1fd7ebf9388b9e3445262b1bd58798a3a2d9d2832cab2f21f7104e3688afb01467ae1'
k2 = '3852a5eaea74c2e07c15a78c5ce6d5778a58d5998eee0421ade2bddf8c527d7c9d85e03e77c3ece257a64806cb11ff168e4e7e4a69140063d8c96c483f4604'
k3_l = 'fc6851611af77ed3b241816041950c9464899c370edb7131913ddb06329ecd85'

# Function analysis
# f(a,b,k) = (a*a+1)*(b*b+1) - 2*(a-b)*(a*b-1) == 4*(int(k, r) + a*b)
# Let's expand and simplify this equation

def expand_equation():
    """
    Let's expand (a*a+1)*(b*b+1) - 2*(a-b)*(a*b-1)
    = (a²+1)(b²+1) - 2(a-b)(ab-1)
    = a²b² + a² + b² + 1 - 2(a²b - a - ab² + b)
    = a²b² + a² + b² + 1 - 2a²b + 2a + 2ab² - 2b
    = a²b² - 2a²b + 2ab² + a² + b² + 2a - 2b + 1
    = ab(ab - 2a + 2b) + a² + b² + 2a - 2b + 1
    
    This should equal 4*(int(k, r) + a*b)
    = 4*int(k, r) + 4*a*b
    
    So: ab(ab - 2a + 2b) + a² + b² + 2a - 2b + 1 = 4*int(k, r) + 4*a*b
    
    Rearranging:
    ab(ab - 2a + 2b - 4) + a² + b² + 2a - 2b + 1 = 4*int(k, r)
    """
    print("Expanded equation:")
    print("ab(ab - 2a + 2b - 4) + a² + b² + 2a - 2b + 1 = 4*int(k, r)")

def f_simplified(a, b, k, r):
    """Simplified version of the constraint function"""
    left = a*b*(a*b - 2*a + 2*b - 4) + a*a + b*b + 2*a - 2*b + 1
    right = 4 * int(k, r)
    return left == right

def solve_for_r():
    """Try to determine the radix r"""
    # Since we have constraints f(x,y,k1), f(y,z,k2), f(z,x,k3)
    # and we know that x,y,z should be reasonable flag values
    # Let's try common radices
    
    possible_r_values = [16, 10, 2, 8, 32]  # Common radices
    
    for r in possible_r_values:
        print(f"\nTrying r = {r}")
        try:
            k1_int = int(k1, r)
            k2_int = int(k2, r)
            print(f"k1 in base {r}: {k1_int}")
            print(f"k2 in base {r}: {k2_int}")
            
            # Check if these are reasonable values
            if k1_int > 0 and k2_int > 0:
                print(f"Base {r} seems valid")
                # Try to find small solutions
                test_small_values(r)
        except ValueError:
            print(f"Invalid base {r} for given keys")

def test_small_values(r):
    """Test with small values to see if we can find patterns"""
    k1_int = int(k1, r)
    k2_int = int(k2, r)
    
    # Try small values for x, y, z (representing parts of the flag)
    for x in range(256, 1000):  # Assuming flag parts are at least 1 byte
        for y in range(256, 1000):
            # Check if f(x, y, k1) holds
            left = x*y*(x*y - 2*x + 2*y - 4) + x*x + y*y + 2*x - 2*y + 1
            if left == 4 * (k1_int + x*y):
                print(f"Found potential solution: x={x}, y={y}")
                # Now try to find z
                for z in range(256, 1000):
                    left2 = y*z*(y*z - 2*y + 2*z - 4) + y*y + z*z + 2*y - 2*z + 1
                    if left2 == 4 * (k2_int + y*z):
                        print(f"Found y={y}, z={z}")
                        # Check if we can determine k3_r
                        return (x, y, z)
    return None

def brute_force_k3_r(x, y, z, r):
    """Try to find k3_r given x, y, z"""
    # We know f(z, x, k3) must hold
    # k3 = k3_l + k3_r
    
    left = z*x*(z*x - 2*z + 2*x - 4) + z*z + x*x + 2*z - 2*x + 1
    target_k3_int = (left - 4*z*x) // 4
    
    print(f"Target k3 (decimal): {target_k3_int}")
    
    # Convert to the same base as other keys
    k3_l_int = int(k3_l, r)
    k3_r_needed = target_k3_int - k3_l_int
    
    print(f"k3_l (decimal): {k3_l_int}")
    print(f"k3_r needed (decimal): {k3_r_needed}")
    
    if k3_r_needed > 0:
        k3_r_hex = hex(k3_r_needed)[2:]  # Remove '0x' prefix
        return k3_r_hex
    
    return None

# Main solving process
print("CTF Crypto Challenge Solver")
print("="*40)

expand_equation()
print("\nTrying to determine the radix...")
solve_for_r()

# Let's try r=16 (hexadecimal) as it's most common for crypto challenges
r = 16
print(f"\nAssuming r = {r} (hexadecimal)")

# Try a more systematic approach
# The constraints are quite complex, let's try a different angle
def alternative_approach():
    """
    Try a more comprehensive approach with larger search space
    """
    r = 16
    k1_val = int(k1, r)
    k2_val = int(k2, r)
    
    print(f"k1 = {k1_val}")
    print(f"k2 = {k2_val}")
    
    # Try broader search - flag parts might be larger numbers
    print("Attempting comprehensive search...")
    
    # First, let's try some typical flag values
    # CTF flags often have format like CTF{...} or flag{...}
    
    # Try small integer values first (faster)
    for x in range(1, 1000):
        if x % 100 == 0:
            print(f"Trying x = {x}")
        for y in range(1, 1000):
            if check_constraint(x, y, k1_val):
                print(f"Found constraint 1: x={x}, y={y}")
                
                for z in range(1, 1000):
                    if check_constraint(y, z, k2_val):
                        print(f"Found constraint 2: y={y}, z={z}")
                        
                        # Check if third constraint can be satisfied
                        k3_r = find_k3_r(z, x, r)
                        if k3_r and len(k3_r) <= 64:  # reasonable length
                            print(f"Potential solution found!")
                            print(f"x={x}, y={y}, z={z}")
                            print(f"k3_r = {k3_r}")
                            
                            # Verify the third constraint
                            k3_full = k3_l + k3_r
                            k3_val = int(k3_full, r)
                            if check_constraint(z, x, k3_val):
                                print("Third constraint verified!")
                                return (x, y, z, k3_r)
    
    print("No solution found in small integer range. Trying ASCII range...")
    
    # Try ASCII range
    for x in range(32, 127):  # ASCII printable
        for y in range(32, 127):
            if check_constraint(x, y, k1_val):
                print(f"ASCII constraint 1: x={x} ('{chr(x)}'), y={y} ('{chr(y)}')")
                
                for z in range(32, 127):
                    if check_constraint(y, z, k2_val):
                        k3_r = find_k3_r(z, x, r)
                        if k3_r:
                            k3_full = k3_l + k3_r
                            k3_val = int(k3_full, r)
                            if check_constraint(z, x, k3_val):
                                return (x, y, z, k3_r)
    
    return None

def check_constraint(a, b, k_val):
    """Check if the constraint equation holds"""
    left = a*b*(a*b - 2*a + 2*b - 4) + a*a + b*b + 2*a - 2*b + 1
    right = 4 * (k_val + a*b)
    return left == right

def find_k3_r(z, x, r):
    """Find k3_r given z, x, and r"""
    # We need f(z, x, k3) to hold
    left = z*x*(z*x - 2*z + 2*x - 4) + z*z + x*x + 2*z - 2*x + 1
    needed_k3_val = (left - 4*z*x) // 4
    
    k3_l_val = int(k3_l, r)
    k3_r_val = needed_k3_val - k3_l_val
    
    if k3_r_val > 0:
        return hex(k3_r_val)[2:].zfill(len(k3_l))  # Pad to same length as k3_l
    return None

print("\nTrying alternative approach...")
result = alternative_approach()

if result:
    x, y, z, k3_r = result
    print(f"\nSolution found!")
    print(f"x = {x}, y = {y}, z = {z}")
    print(f"k3_r = {k3_r}")
    
    # Convert back to flag parts
    m1 = long_to_bytes(x)
    m2 = long_to_bytes(y) 
    m3 = long_to_bytes(z)
    flag = m1 + m2 + m3
    print(f"Flag: {flag}")
else:
    print("No solution found with current approach. May need to expand search space or try different strategy.")