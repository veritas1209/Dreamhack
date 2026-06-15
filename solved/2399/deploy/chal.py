from Crypto.Util.number import getPrime
import random

class Schnorsa:
    def __init__(self, bits=1024):
        self.nb = bits
        self.p = getPrime(bits // 2)
        self.q = getPrime(bits // 2)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = 0x10001
        self.x = random.randint(1, self.n - 1)
        self.g = 2
        self.y = pow(self.g, self.x, self.n)
        self.nk = random.getrandbits(self.nb)
    
    def pub(self):
        return (self.e, self.phi, self.n, self.y)
    
    def get_nonce(self):
        ret = self.nk
        b = self.nb >> 4

        x = self.nk
        for i in range(self.nb // 3):
            x ^= self.nk >> (3 * i)
        x &= (1 << b) - 1

        self.nk = (self.nk << b) | x
        self.nk &= (1 << self.nb) - 1

        return ret
    
    def sign(self, msg):
        k = self.get_nonce()
        t = pow(self.g, k, self.n)
        r = pow((t << self.nb) | msg, self.e, self.n)
        s = (k + self.x * r) % self.phi

        return r, s
    
    def verify(self, msg, sig):
        r, s = sig
        t = pow(self.g, s, self.n) * pow(self.y, -r, self.n) % self.n

        print(t)
        print(r)

        return r == pow((t << self.nb) | msg, self.e, self.n)


if __name__ == "__main__":
    sys = Schnorsa()
    print(f"Pubkey: {sys.pub()}")

    for _ in range(5):
        i = int(input("> "))

        if i == 0:
            msg = int(input("m: "))
            sig = sys.sign(msg)
            print(f"Sig: {sig}")
        elif i == 1:
            msg = int(input("m: "))
            r = int(input("r: "))
            s = int(input("s: "))
            res = sys.verify(msg, (r, s))
            print(f"Result: {res}")
        elif i == 2:
            x = int(input("x: "))
            if x == sys.x:
                print("WOW")
                with open("flag", "r") as f:
                    print(f"Flag: {f.read()}")
            else:
                print(":(")
            exit(0)
