import struct
import os

def analyze_ld():
    if not os.path.exists("ld_hacked.bin"):
        print("[-] ld_hacked.bin file not found.")
        return

    with open("ld_hacked.bin", "rb") as f:
        data = f.read()

    print(f"[*] Analyzing ld_hacked.bin ({len(data)} bytes)...")

    # 1. 'la_activity' 문자열 위치 찾기
    str_offset = data.find(b"la_activity\x00")
    if str_offset == -1:
        print("[-] 'la_activity' string not found.")
        return
    print(f"[+] String 'la_activity' found at offset: {hex(str_offset)}")

    # 2. 참조(Reference) 찾기 (LEA/MOV instruction scanning)
    # x64에서 RIP-relative addressing을 주로 사용하므로,
    # Instruction Pointer(offset) + Instruction Size + Displacement = String Offset
    # Displacement = String Offset - (Current Offset + Instruction Size)
    
    found_ref = False
    vm_entry = 0
    
    print("[*] Scanning for code references...")
    for i in range(0, len(data) - 7):
        # LEA RDI, [RIP + disp] (48 8d 3d ...) 길이 7바이트 가정
        # 또는 다른 레지스터 로드
        
        # 예상되는 Displacement 값 계산 (Instruction 끝이 i+7이라고 가정)
        disp = str_offset - (i + 7)
        
        # 4바이트 범위 내인지 확인
        if -0x80000000 <= disp <= 0x7FFFFFFF:
            # 현재 위치(i+3)에 그 값이 있는지 확인
            try:
                val = struct.unpack("<i", data[i+3:i+7])[0]
                if val == disp:
                    # LEA opcode 확인 (48 8d ...)
                    if data[i] == 0x48 and data[i+1] == 0x8d:
                        print(f"[!] Found LEA reference at {hex(i)}")
                        print(f"    Code: {data[i:i+16].hex()}")
                        vm_entry = i
                        found_ref = True
            except:
                pass
                
    if not found_ref:
        print("[-] Direct reference not found. Trying 0x36371 area...")
        vm_entry = 0x36371 # 사용자 제보 위치
    
    # 3. 코드 영역 덤프 (VM Main Logic)
    # VM 진입점 주변을 덤프하여 연산자를 찾습니다.
    # ADD (01 ..), XOR (31 ..), SUB (29 ..)
    print(f"\n[*] Hex Dump around VM Entry ({hex(vm_entry)}):")
    context = data[vm_entry:vm_entry+64]
    print(context.hex())
    
    # 간단한 패턴 매칭으로 연산자 추측
    # 48 01 / 48 03 -> ADD r64, r64
    # 48 31 / 48 33 -> XOR r64, r64
    if b'\x48\x01' in context or b'\x48\x03' in context:
        print("\n[?] Suspicious Opcode: ADD detected!")
    if b'\x48\x31' in context or b'\x48\x33' in context:
        print("\n[?] Suspicious Opcode: XOR detected!")

analyze_ld()