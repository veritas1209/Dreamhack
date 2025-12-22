# SageMath built-in functions only - no Crypto library needed!

# Given values
n = 24998297096673150182169249215362354242007739410413318575126157135522454459650464839515367449973589872351881588111232458359974156442759925478269348164600608994047506827654217250363002726550685615195642603168866469240543854748805930296027622682611606161248677612758987033657190784676451784033316444357416540404528215755182617067978225391180373837618722386579966738041103029246826236268998063730920284199010801978445169850020974296002328912355942246224612047246859607259251694465518357860628929093115820723422805933720160134026887165191219451114178035318550244534948457197309229817069441497372353040006761953630520952319
e = 219036592185538135344738307892518971121
ciphertext = 22492103123920788566454020484604339106134872650742745073391512501050506129771305948928035866535637341505425529084179721882383102079143024731397748507187387934275458350642485568464490304178775216945067031543580644415604813201561755934104373446659569197912824406390477678269408665711776195005658698163441877602214914022338234828353522009440871618156310903726242712995717883683584295220123698766729160977264967508521147707627483921014457438490696390810954428796570691819519425176749918009488582858075560919673618171630106427382202899839616189777693069389827244665900578389930978934439293709745792001621534806757068565505
MSB = 177376544737836537358848709698797910837308855345061193615390947134942814024740805585465865242303830353471802614674176223815624459859801244223738281190255897249400782766885506935974648077631183301125138497014459511575357027735370348650450059315998401755052098075642617236823830493603351432334099401848913920000

# Parameters
beta = 0.4
epsilon = beta ** 2 / 7
upper_bound = 1024  # p is 1024 bits
lower_bound = int(2048 * (beta ** 2 - epsilon))

print(f"Upper bound: {upper_bound}")
print(f"Lower bound: {lower_bound}")
print(f"Known bits: {upper_bound - lower_bound}")

# Helper function to convert long to bytes (SageMath compatible)
def long_to_bytes(n):
    return int(n).to_bytes((int(n).bit_length() + 7) // 8, 'big')

# MSB represents the high bits of p
# p = MSB + unknown_bits
# where unknown_bits < 2^lower_bound

# Use Coppersmith's method
# Create polynomial ring
P.<x> = PolynomialRing(Zmod(n))

# p = MSB + x where x is the unknown lower bits
# We know that (MSB + x) | n
f = MSB + x

# Use small_roots to find x
X = 2^lower_bound  # upper bound for x
print(f"\nSearching for roots with X = 2^{lower_bound}")

try:
    roots = f.small_roots(X=X, beta=0.4)
    
    if roots:
        print(f"\nFound {len(roots)} root(s)!")
        
        for root in roots:
            p_candidate = int(MSB + root)
            
            # Verify if this is the correct p
            if n % p_candidate == 0:
                p = p_candidate
                q = n // p
                
                print(f"\n✓ Found valid factors!")
                print(f"p = {p}")
                print(f"q = {q}")
                print(f"p * q == n: {p * q == n}")
                
                # Compute private key
                phi = (p - 1) * (q - 1)
                d = inverse_mod(Integer(e), Integer(phi))
                
                # Decrypt the flag
                m = power_mod(Integer(ciphertext), Integer(d), Integer(n))
                flag = long_to_bytes(m)
                
                print(f"\n{'='*50}")
                print(f"FLAG: {flag.decode()}")
                print(f"{'='*50}")
                break
    else:
        print("No roots found. Trying alternative parameters...")
        
        # Try with different beta values
        for beta_try in [0.45, 0.5, 0.35]:
            print(f"\nTrying beta = {beta_try}")
            roots = f.small_roots(X=X, beta=beta_try)
            if roots:
                print(f"Found roots with beta = {beta_try}")
                for root in roots:
                    p_candidate = int(MSB + root)
                    if n % p_candidate == 0:
                        p = p_candidate
                        q = n // p
                        phi = (p - 1) * (q - 1)
                        d = inverse_mod(Integer(e), Integer(phi))
                        m = power_mod(Integer(ciphertext), Integer(d), Integer(n))
                        flag = long_to_bytes(m)
                        print(f"\nFLAG: {flag.decode()}")
                        break
                break
                
except Exception as ex:
    print(f"Error: {ex}")
    print("\nNote: This script requires SageMath to run.")
    print("Install SageMath or run in a SageMath environment.")