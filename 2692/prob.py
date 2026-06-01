from os import urandom
import signal

from cipher import URANUS

TIMEOUT = 60

key = urandom(16)
cipher = URANUS(key)

def timeout(signum,frame):
    print("TIMEOUT!!!")
    exit(0)

signal.signal(signal.SIGALRM, timeout)
signal.alarm(TIMEOUT)

while True:
    msg = input("> ").strip()
    if msg[:7] == "SUBMIT ":
        if msg[7:] == key.hex():
            print(open("flag","r").read().strip())
        else:
            print("Wrong!")
        exit(0)
    msg = bytes.fromhex(msg)
    print(cipher.encrypt(msg).hex())