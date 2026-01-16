import struct

def solve():
    # 1. 스택에 하드코딩된 암호화 데이터 (Little Endian)
    # 기드라 FUN_00101576에서 추출한 값들입니다.
    # Stack Layout: local_298 (Low Addr) -> ... -> local_248 (High Addr)
    encrypted_chunks = [
        0x24243a52447c3b48, # local_298
        0x3936453678377c24, # local_290
        0x5125262c27362469, # local_288
        0x42656a47403f2424, # local_280
        0x3f43247a646f566d, # local_278
        0x3e2e7b6837632424, # local_270
        0x2424512539673c6a, # local_268
        0x2424244626303851, # local_260
        0x3d404c3524553566, # local_258
        0x7c3a323953385461, # local_250
    ]
    
    # 마지막 조각은 5바이트 (MOV RAX, 0x21432e2631)
    last_chunk = 0x21432e2631
    
    # 데이터를 바이트열로 결합
    payload = b''
    for chunk in encrypted_chunks:
        payload += struct.pack('<Q', chunk) # 64-bit Little Endian
    payload += struct.pack('<Q', last_chunk)[:5] # 5 bytes only

    print(f"[+] Encrypted Payload Size: {len(payload)} bytes")
    print(f"[+] Payload Preview: {payload[:20]}...")

    # 2. Decoding Logic (Reversed from FUN_00101180)
    # Custom Base91 Decoder
    
    decoded_data = bytearray()
    state = 0x1f  # Initial State (local_1c)
    
    ptr = 0
    while ptr < len(payload):
        # Null bytes skip logic (from assembly)
        while ptr < len(payload) and payload[ptr] == 0:
            ptr += 1
        if ptr >= len(payload): break
            
        c1 = payload[ptr]
        if c1 <= 0x23: # Terminates if char <= '#' (0x23)
            break
        ptr += 1
        
        # Get next non-null char
        while ptr < len(payload) and payload[ptr] == 0:
            ptr += 1
        if ptr >= len(payload): break
            
        c2 = payload[ptr]
        ptr += 1
        
        # Calculation: 
        # local_1c = (local_1c << 13) + (c2 * 91) + c1 - 0xcf0
        state = (state << 13) + (c2 * 91) + c1 - 0xcf0
        
        # Output Loop
        # while ((state & 0x1000) != 0)
        while (state & 0x1000) != 0:
            byte_out = state & 0xff
            decoded_data.append(byte_out)
            state >>= 8
            
    print(f"[+] Decoded Data Size: {len(decoded_data)} bytes")
    
    # 3. 결과 저장
    with open('vm_bytecode.bin', 'wb') as f:
        f.write(decoded_data)
    print("[+] Saved to 'vm_bytecode.bin'")

    # Hex view for quick check
    print("\n[Dump Head]")
    for i in range(min(16, len(decoded_data))):
        print(f"{decoded_data[i]:02x}", end=' ')
    print()

if __name__ == '__main__':
    solve()