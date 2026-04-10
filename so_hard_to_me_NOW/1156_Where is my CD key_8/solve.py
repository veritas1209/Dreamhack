from Crypto.Cipher import ChaCha20, Salsa20

def solve_final():
    key = bytes.fromhex("d2e0e92b81be46da062780100e7e98d82a81fc207acf02944408d4a6fce175eb")
    
    # 1. Nonce Prefix (Opcode 바로 뒤 6바이트)
    nonce_prefix = bytes([0x77, 0x08, 0x80, 0x00, 0x3f, 0x1a])
    nonce = nonce_prefix + b"rbtree"

    # 2. Ciphertext 추출 (오프셋 재조정: +8이 아니라 +6인 3f 1a부터 시작)
    # 덤프의 0x55555558907d 주소 0x3f 부터 20바이트
    full_dump = bytes([
        0x0f, 0x0b, 0x77, 0x08, 0x80, 0x00, 0x3f, 0x1a, 
        0x3a, 0x2a, 0x33, 0x24, 0x22, 0x00, 0x00, 0x00, 
        0x00, 0x14, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x00, 
        0x00, 0x60
    ])
    
    # 여러 시작점(오프셋) 시도
    # Opcode(2) + Nonce(6) = 8바이트 뒤부터가 정석이지만, 
    # 분석상 6바이트 뒤(3f 1a)일 가능성도 큼
    for offset in [6, 8]:
        ciphertext = full_dump[offset:offset+20]
        
        print(f"\n[TRY] Offset {offset} | Cipher: {ciphertext.hex()}")
        
        # ChaCha20 시도
        try:
            cipher = ChaCha20.new(key=key, nonce=nonce)
            dec = cipher.decrypt(ciphertext)
            res = "".join(chr(b) if 32 <= b <= 126 else "." for b in dec)
            print(f"  [ChaCha20] -> {res}")
        except: pass

        # Salsa20 시도 (Nonce 8바이트 사용)
        try:
            cipher = Salsa20.new(key=key, nonce=nonce[:8])
            dec = cipher.decrypt(ciphertext)
            res = "".join(chr(b) if 32 <= b <= 126 else "." for b in dec)
            print(f"  [Salsa20 ] -> {res}")
        except: pass

if __name__ == "__main__":
    solve_final()