import numpy as np
import json

try:
    from secret import MATRIX_M, VECTOR_V, FLAG, SAMPLES
except ImportError:
    MATRIX_M = None
    VECTOR_V = None
    FLAG = "B1N4RY{DUMMY}"
    SAMPLES = []

MOD = 10**9 + 7
DIM = 6

def encrypt(p):
    v = np.array(p)
    return ((np.dot(MATRIX_M, v) + VECTOR_V) % MOD).tolist()

if __name__ == "__main__":
    with open("output.txt", "w") as f:
        for p in SAMPLES:
            c = encrypt(p)
            f.write(f"{json.dumps(p)} {json.dumps(c)}\n")

        enc_flag = []
        for i in range(0, len(FLAG), DIM):
            block = [ord(x) for x in FLAG[i:i+DIM]]
            if len(block) < DIM:
                block += [0] * (DIM - len(block))
            enc_flag.extend(encrypt(block))
            
        f.write(f"{json.dumps(enc_flag)}")