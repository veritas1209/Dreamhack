import random
import os
from Crypto.Util.number import getPrime, isPrime, bytes_to_long

def complex_add(z1, z2): return (z1[0] + z2[0], z1[1] + z2[1])
def complex_mul(z1, z2): return (z1[0]*z2[0] - z1[1]*z2[1], z1[0]*z2[1] + z1[1]*z2[0])
def energy_norm(z): return z[0]**2 + z[1]**2
def complex_mod(z, m): return (z[0] % m, z[1] % m)

def transmit(base, exp, mod):
    def c_divmod(z1, z2):
        denom = energy_norm(z2)
        numer = complex_mul(z1, (z2[0], -z2[1]))
        q_real = (numer[0] + denom // 2) // denom
        q_imag = (numer[1] + denom // 2) // denom
        q = (q_real, q_imag)
        rem = complex_add(z1, complex_mul(q, (-z2[0], -z2[1])))
        return q, rem
    
    res = (1, 0)
    base_val = base
    while exp > 0:
        if exp % 2 == 1: _, res = c_divmod(complex_mul(res, base_val), mod)
        _, base_val = c_divmod(complex_mul(base_val, base_val), mod)
        exp //= 2
    return res

# [1] LWE Oracle
def generate_lwe_instance(secret_vector):
    LWE_MOD = getPrime(64)
    A = (random.randint(0, LWE_MOD), random.randint(0, LWE_MOD))
    
    # Error is small enough for LWE assumption, but large enough to prevent brute-force.
    Ex = random.randint(-100000, 100000)
    Ey = random.randint(-100000, 100000)
    E = (Ex, Ey)
    
    # B = A * S + E (mod M)
    AS = complex_mul(A, secret_vector)
    B = complex_mod(complex_add(AS, E), LWE_MOD)
    
    return LWE_MOD, A, B

# [2] Key Generation Logic (Now Visible!)
def generate_entangled_keys(bits, drift):
    # Public Constant G
    gx = random.getrandbits(bits // 2)
    gy = random.getrandbits(bits // 2)
    G = (gx, gy) 

    while True:
        # 1. Generate Gaussian Prime Alpha
        r = random.getrandbits(bits)
        i = random.getrandbits(bits)
        if r % 2 == 0: r += 1
        Alpha = (r, i)

        if isPrime(energy_norm(Alpha)):
            # 2. Beta is entangled with Alpha: Beta = Alpha * G + Drift
            # This logic is crucial for the challenge.
            Alpha_G = complex_mul(Alpha, G)
            Beta = complex_add(Alpha_G, drift)
            
            if isPrime(energy_norm(Beta)):
                return Alpha, Beta, G

if __name__ == "__main__":
    # --- [REDACTED SECRET CONSTANTS] ---
    FLAG = b"INCOGNITO{REDACTED}"
    
    # Secret Drift Vector S (Unknown to attacker)
    dx = random.randint(100000, 900000)
    dy = random.randint(100000, 900000)
    real_drift = (dx, dy)

    # 1. Publish LWE Instance (Leak information about Drift)
    lwe_q, lwe_a, lwe_b = generate_lwe_instance(real_drift)

    # 2. Generate RSA Keys based on Drift
    Alpha, Beta, G_const = generate_entangled_keys(512, real_drift)
    Modulus = complex_mul(Alpha, Beta)
    Exponent = 65537

    # 3. Encrypt Flag
    L = len(FLAG) // 2
    Message = (bytes_to_long(FLAG[:L]), bytes_to_long(FLAG[L:]))
    Cipher = transmit(Message, Exponent, Modulus)
    
    # Output Format
    print(f"{lwe_q=}")
    print(f"{lwe_a=}")
    print(f"{lwe_b=}")
    print(f"N={Modulus}")
    print(f"G={G_const}")
    print(f"e={Exponent}")
    print(f"C={Cipher}")