import unicodedata
import hashlib

def checker(user_input):
    test = unicodedata.normalize('NFKC', user_input)
    if user_input!=test:
        return False
    if len(user_input)>100:
        return False
    for i in range(0,len(test),1):
        x=test[i]
        if not (ord(x)>=33 and ord(x)<=126):
            return False
    return True

GOAL = 5
found = 0
record = []
 
print("Input your RootCoin!")
while True:
    attempt=input('> ')
    test=attempt.encode()
    result=hashlib.sha256(test).hexdigest()
    if checker(attempt)==True and result.startswith('deadbeef'):
        if attempt not in record:
            record.append(attempt)
            found+=1
            print(f"You found {found} RootCoin(s)!")
            if found == GOAL:
                with open('flag.txt','rt') as f:
                    FLAG = f.read()
                    print("Flag is "+FLAG)
        else:
            print("You already submitted this RootCoin!")
    else:
        print("Not a valid RootCoin!")