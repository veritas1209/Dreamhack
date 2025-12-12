from pwn import *
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
import hashlib

host='host8.dreamhack.games'
port=19184  # 서버 주소 설정

p=remote(host,port)

# 키 교환에 사용하는 공개 제수
p.recvuntil(b'Prime: ')
div=int(p.recvline()[:-1].decode(),16) # 공개 제수 p
goal=[3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199] # 3 이상의 작은 소수들. (p-1)이 이 수들 중 하나로 나누어지면 좋다.
factor=0

for x in goal: # (p-1)을 이 수들 중 하나로 나눈다.
    if (div-1)%x==0:
        factor=x # 작은 소인수를 하나 선택한다.
        break

if factor!=0:
    try:
        print('Factor = ',str(factor))
        power=(div-1)//factor # 2의 거듭제곱의 지수 중 약한 지수를 선택하기
        target=pow(2,power,div) # 이 수는 제수 power에 대한 위수가 낮다. 편의상 t라 부른다.
        # Alice는 Bob에게 (2^a) mod p를 전송. a는 Alice가 생각한 값이다.
        p.recvuntil(b'Alice sends her key to Bob. Key: ')
        alice=int(p.recvline()[:-1].decode(),16)
        to_bob=pow(alice,power,div) # 2^a 에 power 거듭제곱을 하면 t^a가 된다.
        p.sendlineafter(b'>> ',str(to_bob).encode()) # Bob에게 (t^a)를 전송하기

        # Bob은 Alice에게 (2^b) mod p를 전송. b는 Bob이 생각한 값이다.
        p.recvuntil(b'Bob sends his key to Alice. Key: ')
        bob=int(p.recvline()[:-1].decode(),16)
        to_alice=pow(bob,power,div)
        p.sendlineafter(b'>> ',str(to_alice).encode()) # Alice에게 (t^b)를 전송하기

        # 이제 두 사람은 t^(ab) mod p 를 키로 갖는다. a,b를 구해야 한다.
        p.recvuntil(b'Alice: ')
        enc_alice=bytes.fromhex(p.recvline()[:-1].decode())
        p.recvuntil(b'Bob: ')
        enc_bob=bytes.fromhex(p.recvline()[:-1].decode())
        p.close()
        # t의 위수가 낮다는 점을 이용, 브루트포스를 통해 맞는 것을 하나 구한다.
        for i in range(1,factor,1):
            for j in range(1,factor,1):
                ti=pow(target,i,div) # t^a. to_bob과 같아야 한다.
                tj=pow(target,j,div) # t_b. to_alice와 같아야 한다.
                if ti==to_bob and tj==to_alice: # 맞는 조합을 찾았다면 플래그 획득하기
                    k=pow(target,i*j,div)
                    key=hashlib.md5(str(k).encode()).digest()
                    cipher=AES.new(key,AES.MODE_ECB)
                    flag_alice=unpad(cipher.decrypt(enc_alice),16)
                    flag_bob=unpad(cipher.decrypt(enc_bob),16)
                    flag=(flag_alice+flag_bob).decode()
                    print('Flag : '+flag)
                    break
    except: # 전달한 키가 잘못된 경우
        p.close()
        print('Illegal key. Try again.')
else: # (p-1)이 적당한 소인수를 갖지 않는 경우
    p.close()
    print('Unable to find good factor. try again.')
