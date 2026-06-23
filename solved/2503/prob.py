#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from os import urandom

cache = {}
def give_or_not(inp,result):
    if inp not in cache:
        cache[inp] = urandom(1)[0]&1
    give = cache[inp]
    if give:
        return result
    else:
        return None

key = urandom(16)
def get_instance(iv=None):
    if iv == None:
        iv = urandom(16)
    return iv,AES.new(key,AES.MODE_CBC,iv=iv)

# Menu 1 - Get a AES-CBC ciphertext of token
token = urandom(16)
def get_encrypted_token():
    iv,cipher = get_instance()
    ct = cipher.encrypt(pad(token,16))
    print(f"{iv.hex()}{ct.hex()}")

# Menu 2 - Use a padding oracle; 50% to discard result
def padding_oracle(inp):
    inp = bytes.fromhex(inp)
    iv,ct = inp[:16],inp[16:]
    if len(iv) != 16 or len(ct) != 16:
        print("Please input only IV and the last block!")
        return

    _,cipher = get_instance(iv)
    pt = cipher.decrypt(ct)

    result = None
    try:
        _ = unpad(pt,16)
        result = True
    except ValueError:
        result = False
    result = give_or_not(inp,result)

    print(result)

# Menu 3 - Answer check
def submit_answer(inp):
    inp = bytes.fromhex(inp)
    if inp == token:
        FLAG = open("flag","r").read()
        print(FLAG)
    else:
        print("Nope!")
    exit(0) # IMPORTANT: You can submit the answer ONLY ONCE in each connection

def main():
    while True:
        menu = input("Menu >> ")
        if   menu == "1":
            get_encrypted_token()
        elif menu == "2":
            inp = input("Ciphertext (hex) >> ")
            padding_oracle(inp)
        elif menu == "3":
            inp = input("Answer (hex) >> ")
            submit_answer(inp)

main()