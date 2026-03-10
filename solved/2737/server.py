import sys
import os
import struct

class GenesisPRNG:
    def __init__(self, seed):
        self.M = 1 << 48
        self.A = 25214903917
        self.C = 11
        self.state = (seed ^ self.A) & (self.M - 1)
        
    def get_rand(self):
        self.state = (self.state * self.A + self.C) & (self.M - 1)
        return self.state >> 24 

def get_genesis_time():
    try:
        with open("/tmp/genesis_time.txt", "r") as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return 1700000000000

def setup():
    sys.stdin = open(0, 'r', buffering=1)
    sys.stdout = open(1, 'w', buffering=1)
    sys.stderr = open(2, 'w', buffering=1)

def main():
    setup()
    timestamp = get_genesis_time()

    genesis_seed = (timestamp * 0x1337) ^ 0xCAFEBABE
    
    prng = GenesisPRNG(genesis_seed)
    
    admin_pass = f"{prng.get_rand():06x}{prng.get_rand():06x}{prng.get_rand():06x}{prng.get_rand():06x}"
    
    passed_time = struct.unpack('<H', os.urandom(2))[0] % 40000 + 10000
    for _ in range(passed_time):
        prng.get_rand()
        
    guest_token_1 = prng.get_rand()
    guest_token_2 = prng.get_rand()
    
    print(f"Guest Session ID: {guest_token_1:06x}-{guest_token_2:06x}")
    print("\n1. Authenticate as Admin")
    print("2. Exit")
    print("> ", end="")
    
    try:
        choice = input().strip()
        if choice == "1":
            print("Enter Admin Password: ", end="")
            pwd = input().strip()
            
            if pwd == admin_pass:
                print("Authentication Successful. Welcome, Admin.")
                try:
                    with open("flag.txt", "r") as f:
                        print(f.read().strip())
                except:
                    print("Not found flag.txt")
            else:
                print("Authentication Failed.")
        else:
            print("Goodbye.")
    except:
        pass

if __name__ == "__main__":
    main()