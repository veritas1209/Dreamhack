def htod(x):
    if '0' <= x <= '9':
        return int(x)
    elif 'a' <= x <= 'f':
        return ord(x) - ord('a') + 10
    else:
        raise ValueError(f"Invalid hex digit: {x}")

class LFSR:
    def __init__(self, state):
        self.state = state
        self.taps = [32, 22, 2, 1]

    def get_byte(self):
        result = 0
        for _ in range(8):
            result <<= 1
            result |= self.state & 1
            k = 0
            for pos in self.taps:
                k ^= (self.state >> (32 - pos)) & 1
            self.state >>= 1
            self.state |= (k << 31)
        return result

def hexstring_to_bytes(hexstr):
    return bytes([htod(hexstr[i]) * 16 + htod(hexstr[i + 1]) for i in range(0, len(hexstr), 2)])

def is_printable_ascii(byte):
    return 32 <= byte <= 126

def brute_force_lfsr(cipher_hex, known_prefix=b'DH{', max_keys=0xFFFFFFFF):
    ciphertext = hexstring_to_bytes(cipher_hex)
    target_len = len(known_prefix)
    total_len = len(ciphertext)

    for key in range(1, max_keys + 1):
        lfsr = LFSR(key)
        possible = True
        plaintext = bytearray()

        for i in range(target_len):
            byte = ciphertext[i] ^ lfsr.get_byte()
            plaintext.append(byte)
            if byte != known_prefix[i]:
                possible = False
                break

        if not possible:
            continue

        # Try to decode the rest of the ciphertext
        for i in range(target_len, total_len):
            byte = ciphertext[i] ^ lfsr.get_byte()
            plaintext.append(byte)
            if not is_printable_ascii(byte):
                possible = False
                break

        if possible:
            print(f"[+] Possible Decryption: {plaintext.decode()} , Key = {key}")
            return  # Optional: stop at first result

        if key % 100_000_000 == 0:
            print(f"Checked up to key = {key}")

if __name__ == "__main__":
    cipher_hex = "c615a6cbc4bbf37fe65af240813248140925f2afb31f6c6b5bf71cdfa151fcd55999cf95e2eb9313fc75afe39d1bf836ef14931afe19e16a7c16a1bb41d5abe5d124991d"
    brute_force_lfsr(cipher_hex)
