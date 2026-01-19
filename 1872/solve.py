import struct

def find_constants(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    print(f"[*] Scanning {len(data)} bytes for 'imul' constants...")
    
    candidates = set()
    
    # x86-64 imul opcode patterns
    # 69 [ModR/M] [Imm32] : imul reg, reg, imm32
    # 6B [ModR/M] [Imm8]  : imul reg, reg, imm8
    
    for i in range(len(data) - 6):
        # 0x69: imul with 32-bit immediate
        if data[i] == 0x69:
            # 4바이트 상수 추출 (Little Endian)
            val = struct.unpack('<I', data[i+2:i+6])[0]
            
            # 노이즈 필터링 (너무 작거나 뻔한 값 제외)
            if val > 100 and val < 0xFFFFF000: 
                candidates.add(val)
                
        # 0x48 0x69: 64-bit imul with 32-bit immediate
        if data[i] == 0x48 and data[i+1] == 0x69:
            val = struct.unpack('<I', data[i+3:i+7])[0]
            if val > 100 and val < 0xFFFFF000:
                candidates.add(val)

    print("\n[+] Found Potential Constants (Candidate C):")
    sorted_cands = sorted(list(candidates))
    
    for c in sorted_cands:
        # A = 4*C - 2
        A = 4 * c - 2
        print(f"  C = {c:<10} (Hex: {hex(c):<10}) -> A = {A}")

find_constants("jit_code.bin")