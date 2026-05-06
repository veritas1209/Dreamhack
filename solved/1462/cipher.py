from bitstring import BitArray
from Crypto.Util.Padding import pad, unpad

class SPN:
    sbox = (
        0x00, 0x02, 0x04, 0x06, 0x81, 0x83, 0x85, 0x87, 0x82, 0x80, 0x96, 0x84, 0x03, 0x01, 0x07, 0x05, 
        0x51, 0x53, 0x55, 0x57, 0xd8, 0xb2, 0x54, 0xd6, 0xd3, 0xd5, 0xd7, 0xd1, 0xd2, 0x50, 0x5e, 0x44, 
        0x4c, 0x4a, 0xc8, 0x46, 0xcd, 0xc7, 0xc9, 0xcb, 0xce, 0xc4, 0xea, 0x48, 0x4f, 0x4d, 0x4b, 0x69, 
        0x1d, 0x1f, 0x19, 0x0b, 0x9c, 0x9e, 0x98, 0x9a, 0x9f, 0x9d, 0x9b, 0x99, 0x1e, 0x1c, 0x3a, 0x18, 
        0x30, 0x36, 0x74, 0x32, 0xb1, 0xa3, 0xb5, 0xbf, 0xf2, 0x34, 0xb6, 0xb0, 0x33, 0x31, 0x37, 0x35, 
        0x41, 0x63, 0x65, 0x27, 0xe4, 0xe2, 0xe0, 0xe6, 0xeb, 0xe1, 0xe7, 0xf5, 0x42, 0x68, 0x66, 0x64, 
        0x7c, 0x7e, 0x78, 0xfa, 0x7d, 0xff, 0xb9, 0xf3, 0xfe, 0xf4, 0xca, 0xf8, 0x7f, 0xfd, 0x7b, 0x59, 
        0x2d, 0x2f, 0x39, 0x2b, 0xac, 0xee, 0xa8, 0xa2, 0xaf, 0xad, 0xab, 0xa9, 0x2e, 0x24, 0x2a, 0x28, 
        0x08, 0x0e, 0x0d, 0x0a, 0x89, 0x8b, 0x8f, 0x8d, 0x8a, 0x88, 0x8e, 0x8c, 0x1b, 0x09, 0x0f, 0x0c, 
        0x79, 0x5b, 0x5d, 0x5f, 0xda, 0xd0, 0xdc, 0xde, 0xdb, 0xd9, 0xcf, 0xdd, 0x5a, 0x58, 0x56, 0x5c, 
        0xd4, 0x4e, 0x40, 0x62, 0xc5, 0xdf, 0xc3, 0xc1, 0xc6, 0xcc, 0xc2, 0xc0, 0x47, 0x45, 0x43, 0x61, 
        0x11, 0x17, 0x15, 0x13, 0x94, 0x86, 0x90, 0x92, 0x97, 0x95, 0x93, 0x91, 0x16, 0x14, 0x12, 0x10, 
        0x38, 0x1a, 0x3c, 0x3e, 0xbd, 0xbb, 0xf9, 0xb7, 0xbe, 0xb8, 0xba, 0xbc, 0x3b, 0x29, 0x3f, 0x3d, 
        0x49, 0x6b, 0x6d, 0x6f, 0xe8, 0x7a, 0xec, 0xae, 0xe3, 0xe9, 0xef, 0xed, 0x6a, 0x60, 0x6e, 0x6c, 
        0xb4, 0x76, 0x70, 0x72, 0xe5, 0xf7, 0xf1, 0x52, 0xf6, 0xfc, 0xfb, 0xf0, 0x77, 0x75, 0x73, 0x71, 
        0xa5, 0x23, 0x21, 0x67, 0xa4, 0xa6, 0xa0, 0xaa, 0xa7, 0x25, 0xb3, 0xa1, 0x26, 0x2c, 0x22, 0x20
    )
    pbox = (
         0,  8, 16, 24, 32, 40, 48, 56,
         1,  9, 17, 25, 33, 41, 49, 57,
         2, 10, 18, 26, 34, 42, 50, 58,
         3, 11, 19, 27, 35, 43, 51, 59,
         4, 12, 20, 28, 36, 44, 52, 60,
         5, 13, 21, 29, 37, 45, 53, 61,
         6, 14, 22, 30, 38, 46, 54, 62,
         7, 15, 23, 31, 39, 47, 55, 63
    )

    block_size = 8
    rounds = 5

    def __init__(self, key: bytes) -> None:
        assert len(key) == 8
        self.state: BitArray = BitArray()
        self.round_keys = self._key_expansion(key)

    def _key_expansion(self, key: bytes) -> list[BitArray]:
        round_keys = [BitArray(bytes=key)]
        for i in range(0, self.rounds):
            prev_round_key = round_keys[i]
            round_key = BitArray(bin=prev_round_key[-8:].bin)
            round_key.rol(1)
            round_key = BitArray(bytes=bytes([self.sbox[round_key.bytes[0]]]))
            round_key = BitArray(round_key ^ prev_round_key[0:8])
            for i in range(7):
                round_key.append(round_key[i*8:i*8+8] ^ prev_round_key[i*8+8:i*8+16])
            round_keys.append(round_key)
        return round_keys

    def _substitution(self) -> None:
        new_state = BitArray(length=self.block_size*8)
        for i in range(0, self.block_size):
            new_state.overwrite(bytes([self.sbox[self.state.bytes[i]]]), i*8)
        self.state = new_state

    def _substitution_inv(self) -> None:
        new_state = BitArray(length=self.block_size*8)
        for i in range(0, self.block_size):
            new_state.overwrite(bytes([self.sbox.index(self.state.bytes[i])]), i*8)
        self.state = new_state

    def _permuatation(self) -> None:
        new_state = BitArray(length=self.block_size*8)
        for i in range(0, self.block_size*8):
            new_state.set(self.state[i], self.pbox[i])
        self.state = new_state

    def _permuatation_inv(self) -> None:
        new_state = BitArray(length=self.block_size*8)
        for i in range(0, self.block_size*8):
            new_state.set(self.state[i], self.pbox.index(i))
        self.state = new_state

    def _add_round_key(self, round_n: int) -> None:
        self.state = BitArray(self.state ^ self.round_keys[round_n])

    def _encrypt(self) -> None:
        self._add_round_key(0)
        for round_n in range(1, self.rounds):
            self._substitution()
            self._permuatation()
            self._add_round_key(round_n)
        self._substitution()
        self._add_round_key(self.rounds)

    def _decrypt(self) -> None:
        self._add_round_key(self.rounds)
        self._substitution_inv()
        for round_n in range(self.rounds-1, 0, -1):
            self._add_round_key(round_n)
            self._permuatation_inv()
            self._substitution_inv()
        self._add_round_key(0)

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = pad(plaintext, self.block_size)
        ciphertext = b''
        for i in range(0, len(padded), self.block_size):
            self.state = BitArray(bytes = padded[i:i+self.block_size])
            self._encrypt()
            ciphertext += self.state.bytes
        return ciphertext

    def decrypt(self,ciphertext: bytes) -> bytes:
        padded = b''
        for i in range(0, len(ciphertext), self.block_size):
            self.state = BitArray(bytes = ciphertext[i:i+self.block_size])
            self._decrypt()
            padded += self.state.bytes
        plaintext = unpad(padded, self.block_size)
        return plaintext

if __name__ == '__main__':
    import os
    for _ in range(0x1000):
        test_key = os.urandom(8)
        spn = SPN(test_key)
        plain = os.urandom(1)
        cipher = spn.encrypt(plain)
        assert plain == spn.decrypt(cipher)
