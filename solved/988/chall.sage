from Crypto.Util.number import bytes_to_long
from secret import *

N=512
assert len(FLAG)<=N//8

def printM(M):
    M=M.change_ring(ZZ)
    for v in M:
        out=""
        for i in range(0,N,4):
            out+=chr(0x10900+sum(v[i+j]<<j for j in range(4)))
        print(out)
    
print(XXXXXXXXX);printM(P := random_matrix(GF(2),N,N))
print(XXXXXXXXX);printM(v := random_matrix(GF(2),1,N))
print(XXXXXXXXX);printM(w :=v*P^bytes_to_long(FLAG))