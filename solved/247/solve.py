import ctypes
import struct
import hashlib

# 1. Dumped Ciphertext (Target Bytes from 0x555555558020)
encrypted_data = [
    0x66, 0x0c, 0x4c, 0x86, 0xa6, 0x2c, 0x1c, 0x9c,
    0x1c, 0x66, 0x1c, 0x2c, 0x9c, 0x6c, 0xa6, 0xcc,
    0xa6, 0x6c, 0x6c, 0xac, 0xa6, 0xa6, 0x86, 0x4c,
    0x2c, 0x46, 0xec, 0x8c, 0xec, 0x46, 0x8c, 0x9c,
    0x4c, 0xec, 0xc6, 0x66, 0x4c, 0x46, 0x86, 0x4c,
    0xd2
]

# 2. Configuration
TIME_SEED = 0x71ca7800
GLOBAL_KEY = 0x04d2  # From 0x555555558048 (after ptrace bypass)

# Load libc for exact rand() reproduction
libc = ctypes.CDLL("libc.so.6")

def get_md5_key(seed):
    libc.srand(seed)
    r1 = libc.rand()
    r2 = libc.rand()
    val = (r1 + r2) & 0xFFFFFFFF
    # Pack integer to bytes (Little Endian) and hash
    return hashlib.md5(struct.pack("<I", val)).digest()

def bit_reverse_32(n):
    # Reimplement FUN_0010174a (Bit Reversal)
    n = ((n >> 1) & 0x55555555) | ((n * 2) & 0xaaaaaaaa)
    n = ((n >> 2) & 0x33333333) | ((n & 0x33333333) << 2)
    n = ((n >> 4) & 0x0f0f0f0f) | ((n & 0x0f0f0f0f) << 4)
    n = ((n >> 8) & 0x00ff00ff) | ((n & 0x00ff00ff) << 8)
    return ((n << 16) | (n >> 16)) & 0xFFFFFFFF

def decrypt():
    data = list(encrypted_data)
    length = len(data)

    print("[*] Starting Decryption...")

    # Step 1: Reverse "Bit Reversal" (Inverse of FUN_0010174a)
    # The loop processes 4 bytes at a time.
    # Logic: while (i >> 2 <= local_4c) -> processes floor(len/4) integers
    for i in range(0, (length // 4) * 4, 4):
        chunk_val = struct.unpack("<I", bytes(data[i:i+4]))[0]
        reversed_val = bit_reverse_32(chunk_val) # Bit reversal is its own inverse
        data[i:i+4] = list(struct.pack("<I", reversed_val))
    
    print(f"[*] After Bit-Reverse: {bytes(data).hex()}")

    # Step 2: Generate Key (MD5)
    # Logic: Since we forced time, Key1 and Key2 are generated from same seed.
    key = get_md5_key(TIME_SEED)
    print(f"[*] Generated Key: {key.hex()}")

    # Step 3: Reverse "XOR Loop 2"
    for i in range(length):
        k1 = key[(i & 3) << 2]
        k2 = key[(i * 4 + 1) & 0xf]
        k3 = key[(i * 4 + 2) & 0xf]
        k4 = key[(i * 4 + 3) & 0xf]
        data[i] ^= k1 ^ k2 ^ k3 ^ k4

    # Step 4: Reverse "Global Variable XOR"
    # Logic: *(ushort *)(local_40 + local_54 * 2) ^= DAT_00104048
    # Processes length / 2 times
    for i in range(length // 2):
        idx = i * 2
        val = struct.unpack("<H", bytes(data[idx:idx+2]))[0]
        val ^= GLOBAL_KEY
        data[idx:idx+2] = list(struct.pack("<H", val))

    # Step 5: Reverse "XOR Loop 1"
    # Same logic as Step 3
    for i in range(length):
        k1 = key[(i & 3) << 2]
        k2 = key[(i * 4 + 1) & 0xf]
        k3 = key[(i * 4 + 2) & 0xf]
        k4 = key[(i * 4 + 3) & 0xf]
        data[i] ^= k1 ^ k2 ^ k3 ^ k4

    result = bytes(data)
    print(f"\n[+] Decrypted Flag: {result.decode('utf-8', errors='ignore')}")

if __name__ == "__main__":
    decrypt()