#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes, getPrime, GCD
from signal import alarm

dummy1 = getPrime(512)
dummy2 = getPrime(512)
while True:
    p = getPrime(1024)
    q = getPrime(1024)
    e = getPrime(16)
    if GCD((p - 1) * (q - 1), e) == 1:
        break
N = p * q

print("This cute Amo knows nothing. R...R....RSA? Public key?? Don't confuse Amo with that difficult words!!!")
print("Forget about flag. Just give some sweet snacks for Amo :P")
print("1. snack time.")
print("2. Amo's cooking time.")
print("3. Exit")

alarm(500)
while True:
    action = int(input(" > "))
    if action == 1:
        print("How many snacks are you going to give for Amo? > ")
        snack = int(input())
        if snack > 2 ** 16:
            print("That's too much..")
            continue
        
        print("Great snack! In return, I'll give some useless dummies for you :P")
        for i in range(snack):
            dummy = pow(dummy1, e, N)
            print("dummy =", hex(dummy))
            dummy1 += dummy2
    
    elif action == 2:
        print("Oh, do you want to taste my cookie? Throw some ingredients, I'll make it for you!")
        inp = int(input(' > '))
        super_snack = pow(inp, dummy1, dummy2)
        if long_to_bytes(super_snack) == b'SUPER_DELICIOUS_FLAG_FOR_YOU':
            print("Wow, this is masterpiece!")
            print(open('flag','rb').read())
        else:
            exit('Um...YUCK!')

    else:
        exit()