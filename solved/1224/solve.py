import ast
from pwn import *

host='host3.dreamhack.games'
port=21530 # 서버 주소 설정

p=remote(host,port)

p.recvuntil(b'Seed: ')
base=ast.literal_eval(p.readline().decode()) # seed 값

for i in range(0,256,1): # 0에서 255까지 정수 중 하나를 base 배열에 XOR
    attempt=str(' '.join(map(str,[x^i for x in base]))).encode()
    p.sendlineafter(b'Key: ',attempt) # 답안 전송
    result=p.recvline()
    if b'Correct' in result: # 정답을 맞췄으면 종료
        break
    
flag=p.recvline().decode() # 플래그 획득
p.close()
print('Flag : '+flag)
