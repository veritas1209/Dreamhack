#!/usr/bin/env sage

import hashlib
import signal

class OilVinegar:

    @staticmethod
    def make_upper_diagonal(M):
        n = M.ncols()
        for i in range(n):
            for j in range(i + 1, n):
                M[i,j] += M[j,i]
                M[j,i] = 0
        return Matrix(M)
    
    @staticmethod
    def bytes_to_vector(b: bytes):
        return vector(GF(256), [GF(256).fetch_int(v) for v in b])

    @staticmethod
    def vector_to_bytes(vec):
        return bytes(v.integer_representation() for v in vec)

    @staticmethod
    def matrix_to_bytes(mat):
        ret = b""
        for vec in mat:
            ret += OilVinegar.vector_to_bytes(vec)
        return ret
    
    def hash_message(self, msg: bytes):
        H = hashlib.sha256(msg).digest()
        return self.bytes_to_vector(H)

    def __init__(self, n, m):
        assert n > m

        T = random_matrix(GF(256), n)
        while not T.is_invertible():
            T = random_matrix(GF(256), n)

        F, P = [], []
        for k in range(m):
            F_k = Matrix(GF(256), n)
            for i in range(n - m):
                for j in range(i, n):
                    F_k[i, j] = GF(256).random_element()

            P_k = T.transpose() * F_k * T
            P_k = self.make_upper_diagonal(P_k)

            F.append(F_k)
            P.append(P_k)

        self.n, self.m = n, m
        self.P, self.F, self.T = P, F, T
    
    def pubkey(self):
        return b''.join(self.matrix_to_bytes(P_k) for P_k in self.P)

    def privkey(self):
        return b''.join(self.matrix_to_bytes(F_k) for F_k in self.F) + \
            self.matrix_to_bytes(self.T)

    def sign(self, msg: bytes):
        H = self.hash_message(msg)

        while True:
            v = [GF(256).random_element() for _ in range(self.n - self.m)] + [0] * self.m
            v = vector(GF(256), v)

            mat = Matrix(GF(256), [v * F_k for F_k in self.F])
            target = H - mat * v
            try:
                res = mat[:, self.n - self.m:].solve_right(target)
            except ValueError:
                continue

            v = vector(list(v[:self.n - self.m]) + list(res))
            break        
        
        sig = self.T.inverse() * v
        sig = self.vector_to_bytes(sig)

        assert self.verify(msg, sig), "Failed to generate a valid signature"
        return sig
    
    def verify(self, msg: bytes, sig: bytes):
        H = self.hash_message(msg)
        sig = self.bytes_to_vector(sig)
        H_calc = vector(GF(256), [sig * P_k * sig for P_k in self.P])

        return H == H_calc

if __name__ == "__main__":
    ov = OilVinegar(64, 32)
    pubkey = ov.pubkey()
    print(pubkey.hex())
    signal.alarm(60)

    msg = bytes.fromhex(input("msg: ").strip())
    sig = bytes.fromhex(input("sig: ").strip())

    if ov.verify(msg, sig):
        with open('flag', 'r') as f:
            print(f"Here's the flag: {f.read()}")
    else:
        print("Failed.")
    