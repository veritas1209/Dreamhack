import hashlib
import signal
import subprocess

BINARY_PATH = "./main"
STAGE = 20
TIMEOUT = 150

def timeout(signum, frame):
    print("TIMEOUT!!!")
    exit(0)

def stage():
    while True:
        proc = subprocess.run(["./main"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
        if proc.returncode == 0:
            break
    
    # pk, sk, pt, ct
    lines = proc.stdout.decode().strip().split('\n')

    pt = lines[2][5:]
    pt_hash = hashlib.sha256(bytes.fromhex(pt)).hexdigest().upper()

    print(lines[0]) # pk
    print(f"pt(sha256) = {pt_hash}")
    print(lines[3]) # ct

    inp = input("pt? (Uppercase hexademical string) > ")

    if pt == inp:
        return True
    return False
    
def print_flag():
    with open("./flag") as f:
        print("Congratz!")
        print(f"Here is the flag: {f.read()}")

def main():
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(TIMEOUT)

    for st in range(1, STAGE + 1):
        print(f"=== STAGE {st} ===")
        if not stage():
            print(f"Failed...")
            return
        print("Success!!!")

    print_flag()

if __name__ == "__main__":
    main()