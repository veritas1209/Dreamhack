from utils import *

class GHOST:
    sbox = (
        (0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1),
        (0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF),
        (0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0),
        (0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB),
        (0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC),
        (0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0),
        (0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7),
        (0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2)
    )

    def __init__(self, key: bytes) -> None:
        self._block_size = 8
        self._round_keys = self._expand_key(key)
        self._state = []

    def _expand_key(self, key: bytes) -> list[list[int]]:
        assert len(key) == 8
        key_bits = bytes_to_bits(key)
        round_keys: list[list[int]] = []
        for i in range(0, 64, 32):
            round_keys.append(key_bits[i:i+32])
        return round_keys

    def _substitution(self, bit32: list[int]) -> list[int]:
        res: list[int] = []
        for i,j in enumerate(range(0,32,4)):
            res += int_to_bits(self.sbox[7-i][bits_to_int(bit32[j:j+4])], 4)
        return res

    def _round_function(self, round_n: int, is_enc: bool) -> None:
        round_key_idx = round_n%2

        state_hi = self._state[:32]
        state_lo = self._state[32:]

        state_lo = add_mod_2_32(state_lo, self._round_keys[round_key_idx])
        state_lo = self._substitution(state_lo)
        state_lo = rol11(state_lo)
        state_lo = xor_lst(state_lo, state_hi)

        if (is_enc and round_n == 31) or (not is_enc and round_n == 0):
            self._state[:32] = state_lo
        else:
            self._state[:32] = self._state[32:]
            self._state[32:] = state_lo  

    def _encrypt(self, plaintext: bytes) -> bytes:
        self._state = bytes_to_bits(plaintext)
        for i in range(32):
            self._round_function(i, is_enc=True)
        return bits_to_bytes(self._state)

    def _decrypt(self, ciphertext: bytes) -> bytes:
        self._state = bytes_to_bits(ciphertext)
        for i in range(31, -1, -1):
            self._round_function(i, is_enc=False)
        return bits_to_bytes(self._state)

    def encrypt(self, plaintext: bytes) -> bytes:
        assert len(plaintext)%self._block_size == 0
        ciphertext  = b''
        for i in range(0, len(plaintext), self._block_size):
            ciphertext += self._encrypt(plaintext[i:i + self._block_size])
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(ciphertext)%self._block_size == 0
        plaintext  = b''
        for i in range(0, len(ciphertext), self._block_size):
            plaintext += self._decrypt(ciphertext[i:i + self._block_size])
        return plaintext

def test():
    import os
    trial = 0x1000
    for _ in range(trial):
        key = os.urandom(8)
        g = GHOST(key)
        plain = os.urandom(8)
        cipher = g.encrypt(plain)
        assert plain == g.decrypt(cipher)

if __name__ == '__main__':
    test()
