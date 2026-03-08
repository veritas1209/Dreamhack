from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0
b = 0x7
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# secp256k1
E1 = EllipticCurve(Zmod(p), [a, b])
G = E1(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

# ?
E2 = EllipticCurve(Zmod(n), [a, b])


class ECECDSA:
    def __init__(self):
        self.P = E2.random_point()
        self.D = E2.random_point()
        self.d = randint(1, n - 1)
        self.Q = self.d * G
    
    def sign(self, message):
        if isinstance(message, str):
            message = message.encode()
        
        H = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        k = int(self.P.xy()[0])
        self.P = self.P + self.D

        x = int((k * G).xy()[0])
        r = x % n
        s = pow(k, -1, n) * (H + self.d * r) % n

        return r, s

    def verify(self, message, signature):
        if isinstance(message, str):
            message = message.encode()
        
        H = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        r, s = signature

        sinv = pow(s, -1, n)
        T = sinv * H * G + sinv * r * self.Q
        return T.xy()[0] == r


ececdsa = ECECDSA()

print(f"Q = {ececdsa.Q.xy()}")

# ChatGPT gave these
messages = [
    "The quick brown fox jumps over the lazy dog.",
    "Always look on the bright side of life.",
    "To be or not to be, that is the question.",
    "The early bird catches the worm.",
    "Actions speak louder than words.",
    "A picture is worth a thousand words.",
    "When in Rome, do as the Romans do.",
    "You can't judge a book by its cover.",
    "Better late than never.",
    "Practice makes perfect.",
    "A watched pot never boils.",
    "All that glitters is not gold.",
    "Every cloud has a silver lining.",
    "The pen is mightier than the sword.",
    "A journey of a thousand miles begins with a single step.",
    "Absence makes the heart grow fonder.",
    "Beauty is in the eye of the beholder.",
    "Birds of a feather flock together.",
    "Don't bite the hand that feeds you.",
    "Don't count your chickens before they hatch.",
    "Don't put all your eggs in one basket.",
    "Rome wasn't built in a day.",
    "The grass is always greener on the other side.",
    "There's no place like home.",
    "Two heads are better than one."
]

signatures = []
for i, msg in enumerate(messages):
    sig = ececdsa.sign(msg)
    assert ececdsa.verify(msg, sig)
    signatures.append(sig)

print(f"msgs = {messages}")
print(f"sigs = {signatures}")

key = int(ececdsa.d).to_bytes(32, 'big')
cipher = AES.new(key, AES.MODE_ECB)

with open('flag', 'rb') as f:
    flag = f.read()
    enc = cipher.encrypt(pad(flag, 16)).hex()
    print(f"enc = \"{enc}\"")