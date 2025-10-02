import os; from misty1 import Misty1; from secret import flag; print(Misty1(os.urandom(16)).encrypt_block(flag).hex()) # output = 792c6cfd902bbed9


