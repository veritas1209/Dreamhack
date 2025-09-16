from Crypto.Util.number import *
import math

# Given values
k1 = '12815b6189456f7eae8e16eab976bdd2868065e0a0417a1c95fcf75bc1fd7ebf9388b9e3445262b1bd58798a3a2d9d2832cab2f21f7104e3688afb01467ae1'
k2 = '3852a5eaea74c2e07c15a78c5ce6d5778a58d5998eee0421ade2bddf8c527d7c9d85e03e77c3ece257a64806cb11ff168e4e7e4a69140063d8c96c483f4604'
k3_l = 'fc6851611af77ed3b241816041950c9464899c370edb7131913ddb06329ecd85'

def analyze_equation():
    """
    Let's analyze the equation more carefully:
    f(a,b,k) = (a²+1)(b²+1) - 2(a-b)(ab-1) == 4*(int(k, r) + ab)
    
    Expanding the left side:
    (a²+1)(b²+1) = a²b² + a² + b² + 1
    2(a-b)(ab-1) = 2(a²b - a - ab² + b) = 2a²b - 2a - 2ab² + 2b
    
    So: a²b² + a² + b² + 1 - 2a²b + 2a + 2ab² - 2b = 4*(int(k,r) + ab)
    
    Simplifying: a²b² - 2a²b + 2ab² + a² + b² + 2a - 2b + 1 = 4*int(k,r) + 4ab
    
    Rearranging: a²b² - 2a²b + 2ab² - 4ab + a² + b² + 2a - 2b + 1 = 4*int(k,r)
    
    Factor out ab: ab(ab - 2a + 2b - 4) + a² + b² + 2a - 2b + 1 = 4*int(k,r)
    
    Let's try a different factorization approach...
    """
    print("Analyzing the mathematical structure...")
    
    # Let's try to see if there's a pattern by testing with small known values
    # and see what the equation actually computes
    
    test_cases = [(1,1), (1,2), (2,1), (2,2), (3,3)]
    for a, b in test_cases:
        left = (a*a + 1) * (b*b + 1) - 2*(a-b)*(a*b - 1)
        right_part = 4*(a*b)
        k_contribution = left - right_part
        print(f"a={a}, b={b}: left={left}, 4*ab={right_part}, k_part={k_contribution}")

def try_modular_approach():
    """
    Maybe we can use modular arithmetic or look for patterns
    """
    r = 16
    k1_val = int(k1, r)
    k2_val = int(k2, r)
    
    print(f"\nk1 (hex to int): {k1_val}")
    print(f"k2 (hex to int): {k2_val}")
    
    # Let's see if we can find any mathematical relationships
    # Maybe the values are related to some common crypto parameters
    
    # Try to factor or find patterns in k1 and k2
    print(f"k1 bit length: {k1_val.bit_length()}")
    print(f"k2 bit length: {k2_val.bit_length()}")
    
    # Check if they have common factors
    gcd_val = math.gcd(k1_val, k2_val)
    print(f"GCD(k1, k2): {gcd_val}")

def alternative_equation_form():
    """
    Let's try a completely different approach.
    Maybe we can rearrange the equation to solve for one variable at a time.
    
    From: (a²+1)(b²+1) - 2(a-b)(ab-1) = 4*(K + ab)
    where K = int(k, r)
    
    Let's expand and collect terms:
    a²b² + a² + b² + 1 - 2a²b + 2a + 2ab² - 2b = 4K + 4ab
    
    Rearranging to solve for specific relationships:
    a²b² - 2a²b + 2ab² - 4ab + a² + b² + 2a - 2b + 1 - 4K = 0
    
    This is a polynomial in a and b. Let's see if we can solve it systematically.
    """
    
    r = 16
    k1_val = int(k1, r)
    k2_val = int(k2, r)
    
    def equation_residual(a, b, k_val):
        """Calculate how close we are to satisfying the equation"""
        left = (a*a + 1) * (b*b + 1) - 2*(a-b)*(a*b - 1)
        right = 4*(k_val + a*b)
        return abs(left - right)
    
    # Try a wider search with larger step sizes first to identify regions
    print("Searching for approximate solutions...")
    
    best_solutions = []
    
    # Search in a broader range with larger steps
    for x in range(1, 10000, 100):  # Step size 100
        if x % 1000 == 1:
            print(f"Searching around x = {x}")
        for y in range(1, 10000, 100):
            residual1 = equation_residual(x, y, k1_val)
            if residual1 < 1e12:  # If reasonably close
                print(f"Close solution for constraint 1: x={x}, y={y}, residual={residual1}")
                best_solutions.append((x, y, residual1, 1))
    
    # If we found close solutions, search around them more precisely
    for x, y, _, constraint in best_solutions:
        print(f"Refining around x={x}, y={y}")
        for dx in range(-200, 201, 10):
            for dy in range(-200, 201, 10):
                new_x, new_y = x + dx, y + dy
                if new_x > 0 and new_y > 0:
                    residual = equation_residual(new_x, new_y, k1_val)
                    if residual == 0:
                        print(f"EXACT solution found: x={new_x}, y={new_y}")
                        return find_complete_solution(new_x, new_y)
    
    return None

def check_small_prime_solutions():
    """
    CTF problems often have elegant solutions involving small primes or special numbers
    """
    r = 16
    k1_val = int(k1, r)
    k2_val = int(k2, r)
    
    # Try small primes and their combinations
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    
    print("Trying small prime solutions...")
    
    for p1 in primes:
        for p2 in primes:
            if check_exact_constraint(p1, p2, k1_val):
                print(f"Found prime solution for constraint 1: x={p1}, y={p2}")
                
                for p3 in primes:
                    if check_exact_constraint(p2, p3, k2_val):
                        print(f"Found prime solution for constraint 2: y={p2}, z={p3}")
                        return find_complete_solution(p1, p2, p3)
    
    # Try powers of 2
    print("Trying powers of 2...")
    powers_of_2 = [2**i for i in range(1, 20)]
    
    for p1 in powers_of_2:
        for p2 in powers_of_2:
            if check_exact_constraint(p1, p2, k1_val):
                print(f"Found power-of-2 solution: x={p1}, y={p2}")
                
                for p3 in powers_of_2:
                    if check_exact_constraint(p2, p3, k2_val):
                        return find_complete_solution(p1, p2, p3)
    
    return None

def check_exact_constraint(a, b, k_val):
    """Check if the constraint equation holds exactly"""
    left = (a*a + 1) * (b*b + 1) - 2*(a-b)*(a*b - 1)
    right = 4*(k_val + a*b)
    return left == right

def find_complete_solution(x, y, z=None):
    """Given x and y, find z and k3_r"""
    r = 16
    k1_val = int(k1, r)
    k2_val = int(k2, r)
    
    if z is None:
        # Find z from the second constraint
        for test_z in range(1, 10000):
            if check_exact_constraint(y, test_z, k2_val):
                z = test_z
                break
        
        if z is None:
            print("Could not find z")
            return None
    
    # Calculate k3_r
    # We need: f(z, x, k3) = True
    left = (z*z + 1) * (x*x + 1) - 2*(z-x)*(z*x - 1)
    needed_k3_val = (left - 4*z*x) // 4
    
    k3_l_val = int(k3_l, r)
    k3_r_val = needed_k3_val - k3_l_val
    
    if k3_r_val > 0:
        k3_r_hex = hex(k3_r_val)[2:]
        
        # Verify the solution
        k3_full = k3_l + k3_r_hex
        k3_full_val = int(k3_full, r)
        
        if check_exact_constraint(z, x, k3_full_val):
            print(f"Complete solution found!")
            print(f"x = {x}, y = {y}, z = {z}")
            print(f"k3_r = {k3_r_hex}")
            
            # Convert to flag
            try:
                flag_parts = [long_to_bytes(val) for val in [x, y, z]]
                flag = b''.join(flag_parts)
                print(f"Flag: {flag}")
                return (x, y, z, k3_r_hex)
            except:
                print("Could not convert to bytes - values might not represent valid byte strings")
                return (x, y, z, k3_r_hex)
    
    return None

# Let's also try a direct mathematical approach
def solve_quadratic_system():
    """
    The constraint equation might have a more direct mathematical solution
    Let's see if we can solve it as a system of equations
    """
    print("Attempting direct mathematical solution...")
    
    # For the equation: ab(ab - 2a + 2b - 4) + a² + b² + 2a - 2b + 1 = 4K
    # This can be rewritten as a quartic equation in terms of one variable
    
    r = 16
    k1_val = int(k1, r)
    
    print(f"k1 = {k1_val}")
    
    # Let's try some specific cases where the equation might simplify
    # Case 1: a = b (symmetric case)
    print("Trying symmetric case a = b...")
    for a in range(1, 1000):
        if a % 100 == 0:
            print(f"Trying a = b = {a}")
        
        # When a = b: ab(ab - 2a + 2a - 4) + a² + a² + 2a - 2a + 1 = 4K
        # Simplifies to: a²(a² - 4) + 2a² + 1 = 4K
        # Which is: a⁴ - 4a² + 2a² + 1 = 4K
        # Or: a⁴ - 2a² + 1 = 4K
        # This is: (a² - 1)² = 4K
        
        left_val = (a*a - 1)**2
        if left_val == 4 * k1_val:
            print(f"Symmetric solution found: a = b = {a}")
            return find_complete_solution(a, a)
    
    return None

# Main execution
print("CTF Crypto Challenge Advanced Solver")
print("=" * 50)

analyze_equation()
try_modular_approach()

print("\n" + "="*50)
print("Trying mathematical approaches...")

# Try different solution strategies
result = None

result = check_small_prime_solutions()
if not result:
    result = solve_quadratic_system()
if not result:
    result = alternative_equation_form()

if result:
    print(f"\nFinal solution: {result}")
else:
    print("\nNo solution found. The problem might require a different approach or the search space might need to be expanded further.")
    
    # Let's try one more approach - working backwards from typical flag formats
    print("\nTrying flag format analysis...")
    
    # Common CTF flag prefixes when converted to numbers
    common_prefixes = [
        bytes_to_long(b"CTF{"),
        bytes_to_long(b"flag"),
        bytes_to_long(b"FLAG"),
        bytes_to_long(b"DH{"),  # DreamHack format
    ]
    
    r = 16
    k1_val = int(k1, r)
    k2_val = int(k2, r)
    
    for prefix in common_prefixes:
        print(f"Trying prefix: {long_to_bytes(prefix)}")
        for y in range(1, 10000):
            if check_exact_constraint(prefix, y, k1_val):
                print(f"Found match with prefix {long_to_bytes(prefix)}: y={y}")
                result = find_complete_solution(prefix, y)
                if result:
                    break
        if result:
            break