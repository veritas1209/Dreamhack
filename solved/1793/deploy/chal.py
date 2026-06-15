import os

BITMASK_64 = (1 << 64) - 1
NUM_GUESS = 256
NUM_STAGE = 50

def NFSRs(key, iv):
    s1, s2 = key, iv
    result = 0
    for i in range(160 + 8):
        t1 = (s1 >> 30 ^ s1 >> 63) & 1
        t2 = (s2 >> 46 ^ s2 >> 63) & 1
        if i >= 160:
            result |= (t1 ^ t2) << (i - 160)
        t1 ^= (s2 >> 10 & s2 >> 19 ^ s2 >> 56) & 1
        t2 ^= (s1 >> 21 & s1 >> 34 ^ s1 >> 60) & 1

        s1 = (s1 << 1 | t2) & BITMASK_64
        s2 = (s2 << 1 | t1) & BITMASK_64

    return result


def guess():
    if os.urandom(1)[0] & 1:
        is_urandom = False
        key = int.from_bytes(os.urandom(8), 'little')
        rand = lambda iv: NFSRs(key, iv)
    else:
        is_urandom = True
        prevs = dict()
        def rand(iv):
            if iv in prevs:
                return prevs[iv]
            else:
                value = os.urandom(1)[0]
                prevs[iv] = value
                return value

    for _ in range(NUM_GUESS):
        iv = int(input('iv > '))

        if iv < 0 or iv > BITMASK_64:
            break

        result = rand(iv)
        print(f"{result = }")
    
    user_guess = input('Is this urandom? (y/n) ') == 'y'

    return user_guess == is_urandom


def main():
    for stage in range(NUM_STAGE):
        print(f"[STAGE {stage + 1}]")
        if not guess():
            print("Failed :(")
            exit(0)
    
    with open('./flag', 'r') as f:
        flag = f.read()
        print(f"Here is the flag: {flag}")


if __name__ == "__main__":
    main()