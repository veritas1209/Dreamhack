import random
import os

def rand():
    random.seed(os.urandom(16))
    
    outputs = []
    for _ in range(624):
        num = random.getrandbits(31)
        outputs.append(num)
    
    target = random.getrandbits(31)
    
    return outputs, target

def main():

    outputs, target = rand()

    for i in range(0, 624, 8):
        print(" ".join(f"{outputs[j]:10d}" for j in range(i, min(i+8, 624))))
    print()
    
    p = int(input("answer : "))
    
    if p == target:
        print(f"Correct! here is your flag! {FLAG}")
    else:
        print(f"nope!")

if __name__ == "__main__":
    main()