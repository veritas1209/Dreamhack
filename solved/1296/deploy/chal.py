from Crypto.Util.number import getPrime, isPrime
from random import randint

import os
import signal

BLEN = 256
BANNER = open('banner', 'r').read()
FLAG = open('flag', 'r').read()
NUM_SLOTS = 10
TIMEOUT = int(os.environ.get('TIMEOUT', 60))

MENU = """1. Put a plaintext
2. Add ciphertexts
3. Multiply ciphertexts
4. Verify a ciphertext
"""

def timeout(signum, frame):
    print("Timeout!!!")
    signal.alarm(0)
    exit(0)

def next_prime(p):
    p |= 1
    while not isPrime(p):
        p += 2
    return p

def gen_params():
    Q = next_prime(2 ** BLEN)
    p = getPrime(4 * BLEN)
    return p, Q

def enc(p, Q, m):
    qlen, rlen = 1337, 200
    assert rlen < BLEN
    assert qlen > 4 * BLEN
    q = randint(2, 2 ** qlen)
    r = randint(2, 2 ** rlen)

    return p * q + Q * r + m

def dec(p, Q, m):
    return (m % p) % Q

def main():
    print("Future is here...")
    print(BANNER)
    print("=== The Fully Homomorphic Encryption Playground ===\n")

    signal.signal(signal.SIGALRM, timeout)
    p, Q = gen_params()
    slots = [ None ] * NUM_SLOTS

    signal.alarm(TIMEOUT)
    for _ in range(120):
        print(MENU)
        choice = int(input("> "))

        if choice == 1:
            idx = int(input("index > "))
            assert 0 <= idx < NUM_SLOTS
            pt = int(input("plaintext > "))
            assert 0 <= pt < 2 ** BLEN

            e = enc(p, Q, pt)
            slots[idx] = [e, pt]
            print(f"Successfully encrypted {pt}: {e}")
            print(f"Now it's in the slot #{idx}")
        elif choice == 2:
            i = int(input("index 1 > "))
            j = int(input("index 2 > "))
            slots[i] = [(slots[i][0] + slots[j][0]) % p, (slots[i][1] + slots[j][1]) % Q]
            print(f"Added slots #{i} with slots #{j}")
        elif choice == 3:
            i = int(input("index 1 > "))
            j = int(input("index 2 > "))
            slots[i] = [(slots[i][0] * slots[j][0]) % p, (slots[i][1] * slots[j][1]) % Q]
            print(f"Multiplied slots #{i} with slots #{j}")
        elif choice == 4:
            idx = int(input("index > "))
            print(f"Result: {dec(p, Q, slots[idx][0]) == slots[idx][1]}")
        elif choice == 1337:
            guess = int(input("guess > "))
            result = enc(p, Q, 0x13371337)
            if guess == result:
                print(FLAG)
            else:
                exit(0)

if __name__ == "__main__":
    main()