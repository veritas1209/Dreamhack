class OCamlMemoryEmulator:
    def __init__(self):
        self.memory = {}

    def write_64(self, address, value):
        print(f"[DEBUG - MEMORY] 메모리 쓰기 -> 주소: {hex(address)}, 저장된 값: {value}")
        self.memory[address] = value

def ARIA_Add_Round_Key_Port(in_RAX, unaff_RBX, unaff_R14_val, unaff_R15):
    print("="*60)
    print("[DEBUG - START] ARIA_Add_Round_Key 시뮬레이션 함수 시작")
    print(f"[DEBUG - INPUT] in_RAX 초기값: {in_RAX}")
    print(f"[DEBUG - INPUT] unaff_RBX 초기값: {unaff_RBX}")
    print(f"[DEBUG - INPUT] R14 (GC 힙 한계점): {hex(unaff_R14_val)}")
    print(f"[DEBUG - INPUT] R15 (현재 힙 포인터): {hex(unaff_R15)}")
    print("-" * 60)

    mem_emu = OCamlMemoryEmulator()

    # OCaml Minor Heap GC 체크: (unaff_R15 - 0x28 < *unaff_R14)
    target_addr = unaff_R15 - 0x28
    print(f"[DEBUG - LOGIC] 힙 체크 연산: {hex(unaff_R15)} - 0x28 = {hex(target_addr)}")
    
    if target_addr < unaff_R14_val:
        print(f"[DEBUG - GC] 결과: {hex(target_addr)} < {hex(unaff_R14_val)}")
        print("[DEBUG - GC] 힙 메모리 부족 감지! caml_call_gc(...) 호출됨.")
        # GC 호출 후 in_RAX가 새로운 메모리 포인터 등의 결과값으로 갱신됨을 모사
        in_RAX = "GC_COLLECTED_NEW_RAX"
        print(f"[DEBUG - GC] GC 처리 후 in_RAX 값 변경됨: {in_RAX}")
    else:
        print(f"[DEBUG - GC] 결과: {hex(target_addr)} >= {hex(unaff_R14_val)}")
        print("[DEBUG - GC] 힙 메모리 충분. 가비지 컬렉터 건너뜀.")

    print("-" * 60)
    print("[DEBUG - ALLOC] 메모리에 OCaml 배열/객체 헤더 및 데이터 세팅 시작")
    # 메모리 쓰기 작업 (C 코드의 역순/순차적 포인터 대입 로직)
    mem_emu.write_64(unaff_R15 - 0x28, hex(0x10f7))
    mem_emu.write_64(unaff_R15 - 0x20, "FUNCTION_PTR: ARIA_Add_Round_Key")
    mem_emu.write_64(unaff_R15 - 0x18, hex(0x100000000000005))
    mem_emu.write_64(unaff_R15 - 0x10, in_RAX)
    mem_emu.write_64(unaff_R15 - 0x08, unaff_RBX)

    print("-" * 60)
    print("[DEBUG - CALL] caml_make_array() 실행")
    print("[DEBUG - END] 함수 실행 종료")
    print("="*60)

    return mem_emu.memory