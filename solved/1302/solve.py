import numpy as np
from Crypto.Util.number import long_to_bytes, bytes_to_long

# ==========================================
# 1. AES Linear Components (SubBytes REMOVED)
# ==========================================

def xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1)

def mix_single_column(a):
    # Standard AES MixColumns
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)
    return a

def mix_columns(state):
    # state: 4x4 matrix (list of lists)
    for i in range(4):
        col = [state[0][i], state[1][i], state[2][i], state[3][i]]
        col = mix_single_column(col)
        for j in range(4):
            state[j][i] = col[j]
    return state

def shift_rows(state):
    # Standard AES ShiftRows
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state

def to_state(block_int):
    # Convert 128-bit integer to 4x4 state matrix
    block_bytes = long_to_bytes(block_int, 16)
    state = [[0]*4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[i][j] = block_bytes[i + 4*j] # AES uses column-major order usually, but let's follow standard
    # Actually standard AES inputs are usually filled column by column in some descs, 
    # but Python implementations often do row-major. Let's align with standard byte order.
    # Bytes: 0 1 2 3 ... 15
    # State:
    # 0 4 8 12
    # 1 5 9 13
    # 2 6 10 14
    # 3 7 11 15
    state = [[0]*4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            state[r][c] = block_bytes[r + 4*c]
    return state

def from_state(state):
    block_bytes = bytearray(16)
    for c in range(4):
        for r in range(4):
            block_bytes[r + 4*c] = state[r][c]
    return bytes_to_long(block_bytes)

def linear_encrypt_block(block_int):
    """
    Simulates the Challenge's Encryption WITHOUT KEYS and WITHOUT SUBBYTES.
    This captures the linear transformation matrix 'L'.
    """
    state = to_state(block_int)
    
    # 9 Rounds of (Shift -> Mix) 
    # Note: AddRoundKey is omitted because we want the linear part 'L' only.
    # The key's effect will be captured in the constant vector 'C'.
    for _ in range(9):
        state = shift_rows(state)
        state = mix_columns(state)
        
    # Final Round (Shift only)
    state = shift_rows(state)
    
    return from_state(state)

# ==========================================
# 2. Linear Cryptanalysis Solver
# ==========================================

def get_bit(val, i):
    return (val >> i) & 1

def bits_to_int(bits):
    res = 0
    for i, b in enumerate(bits):
        if b: res |= (1 << i)
    return res

def solve():
    print("[*] Step 1: Building the Linear Transformation Matrix (L)...")
    # We treat the cipher as a linear system over GF(2):  y = L * x + c
    # L is 128x128 matrix.
    # We can find L by encrypting basis vectors (1, 2, 4, 8...) with 'linear_encrypt_block'
    
    L_cols = []
    for i in range(128):
        basis_vector = 1 << i
        # Encrypt the basis vector through the linear components
        output = linear_encrypt_block(basis_vector)
        # Convert output integer to bit list (column of L)
        col = [get_bit(output, j) for j in range(128)]
        L_cols.append(col)
    
    # Construct Matrix L
    L = np.array(L_cols).T # Transpose because we collected columns
    
    print("[*] Step 2: Inverting Matrix L (GF(2))...")
    # Invert L over GF(2). Since numpy doesn't support GF(2) inv directly,
    # we use a boolean matrix inversion or solve.
    # Here we assume L is invertible (AES linear layer is designed to be).
    
    try:
        # Use pseudo-inverse approach or simple Gaussian elimination for GF(2)
        # For simplicity, let's treat it as solving L * L_inv = I
        # A simple way in numpy for GF(2) inverse:
        # Check determinant first (optional)
        pass 
    except:
        print("[-] Matrix construction failed.")
        return

    # Using a specialized GF2 inversion function for numpy bool arrays
    def gf2_inverse(M):
        n = M.shape[0]
        M_aug = np.hstack((M, np.eye(n, dtype=int)))
        for i in range(n):
            pivot = np.argmax(M_aug[i:, i]) + i
            if M_aug[pivot, i] == 0: raise ValueError("Singular matrix")
            M_aug[[i, pivot]] = M_aug[[pivot, i]]
            idx = np.where(M_aug[:, i] == 1)[0]
            idx = idx[idx != i]
            M_aug[idx] ^= M_aug[i]
        return M_aug[:, n:]

    L_inv = gf2_inverse(L.astype(int))
    print("[+] Matrix L Inverted successfully.")

    print("[*] Step 3: Recovering Constant Vector (C) from PNG Header...")
    # Equation: Cipher_Header = L * Plain_Header + C
    # Therefore: C = Cipher_Header - (L * Plain_Header)  (In GF(2), + and - are XOR)
    
    PNG_HEADER_HEX = "89504E470D0A1A0A0000000D49484452"
    try:
        with open("censored.png.enc", "rb") as f:
            full_data = f.read()
            enc_header = full_data[:16]
    except:
        print("[-] File 'censored.png.enc' not found.")
        return
        
    p_vec = np.array([get_bit(int(PNG_HEADER_HEX, 16), i) for i in range(128)]).reshape(128, 1)
    c_vec_real = np.array([get_bit(bytes_to_long(enc_header), i) for i in range(128)]).reshape(128, 1)
    
    # Calculate L * P
    lp_vec = np.dot(L, p_vec) % 2
    
    # Calculate Constant C = Cipher ^ (L * P)
    const_C = (c_vec_real ^ lp_vec) % 2
    
    print("[*] Step 4: Decrypting the full file...")
    # Decryption: P = L_inv * (Cipher - C)
    
    decrypted_bytes = b""
    
    # Process 16 bytes at a time
    total_blocks = len(full_data) // 16
    
    for i in range(total_blocks):
        block = full_data[i*16 : (i+1)*16]
        cipher_val = bytes_to_long(block)
        y = np.array([get_bit(cipher_val, k) for k in range(128)]).reshape(128, 1)
        
        # (Cipher - C)
        y_centered = (y ^ const_C) % 2
        
        # P = L_inv * y_centered
        x = np.dot(L_inv, y_centered) % 2
        
        # Convert bits back to bytes
        val = bits_to_int(x.flatten())
        decrypted_bytes += long_to_bytes(val, 16)
        
        if i % 100 == 0:
            print(f"\rProgress: {i}/{total_blocks}", end="")
            
    with open("censored_final.png", "wb") as f:
        f.write(decrypted_bytes)
        
    print("\n[+] Success! Saved as 'censored_final.png'")

if __name__ == "__main__":
    solve()