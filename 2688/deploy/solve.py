import angr
import claripy
import logging
from z3 import *
import struct

# 불필요한 로그 끄기
logging.getLogger('angr').setLevel(logging.CRITICAL)

# -----------------------------------------------------------
# [1] 설정: Opcode 맵핑 & 타겟 데이터
# -----------------------------------------------------------
# 분석 결과에 따른 Opcode 맵핑 (출제자 힌트 + GDB 분석 반영)
# 주의: 0x8049186은 질문글의 ADD가 아니라 MOV가 맞습니다.
OP_MAP = {
    0x8049186: "MOV", 0x80491db: "MUL", 0x8049223: "XOR",
    0x8049267: "AND", 0x80492a8: "OR",  0x8049310: "NOT",
    0x804933a: "SHL", 0x8049376: "SHR", 0x80493b2: "ROL",
    0x80493ee: "ROR", 0x804942a: "DIV", 0x804946a: "MOD",
    0x80494a0: "SUB",
}

# 최종 비교 대상 값 (문제 설명의 a41c... 문자열)
TARGET_HEX = "a41cb7e5560fee35fd56106aa140fd3f1aa35b2ce57252ca251ba7920b12c36ba335b9c2f6d24f10d6b1b16336cab5f108aad2da300be3cabe6e3dc18dbb8675"
TARGET_BYTES = bytes.fromhex(TARGET_HEX)

# Trace 결과를 저장할 리스트
# (OpName, Dest_Addr, Src_Addr, Key_Addr)
trace_log = []

# -----------------------------------------------------------
# [2] Trace 단계: angr로 실행 흐름 녹화 (Concrete Execution)
# -----------------------------------------------------------
def run_tracer():
    print("[*] Phase 1: Tracing operations with angr (Concrete Mode)...")
    
    binary_path = './prob'
    project = angr.Project(binary_path, auto_load_libs=False)
    
    # 훅 함수: 연산을 수행하지 않고 "기록"만 함 (실행은 Python 정수로 대체)
    def hook_tracer(state):
        # 1. 64비트 연산 종류 식별
        target_addr = state.solver.eval(state.memory.load(state.regs.esp, 4, endness='Iend_LE'))
        state.regs.esp += 8 # retf 정리
        
        op_name = OP_MAP.get(target_addr)
        
        # 2. 복귀 주소 (EDI)
        return_addr = state.solver.eval(state.regs.edi)
        
        if op_name:
            # 3. 주소 가져오기 (Src, Key, Dst 포인터)
            src_ptr = state.solver.eval(state.regs.edx)
            key_ptr = state.solver.eval(state.regs.ecx)
            dst_ptr = state.solver.eval(state.regs.esi)
            
            # 4. 로그에 기록 (나중에 Z3가 이걸 보고 식을 세움)
            trace_log.append({
                'op': op_name,
                'dst': dst_ptr,
                'src': src_ptr,
                'key': key_ptr
            })
            
            # 5. 구체적(Concrete) 값으로 연산 수행 (angr가 길을 잃지 않게)
            # 여기서는 심볼릭 변수가 아닌 Python 정수를 사용하므로 매우 빠름
            val_src = state.solver.eval(state.memory.load(src_ptr, 8, endness='Iend_LE'))
            val_key = state.solver.eval(state.memory.load(key_ptr, 8, endness='Iend_LE'))
            
            res = 0
            if op_name == "MOV": res = val_src
            elif op_name == "MUL": res = (val_src * val_key)
            elif op_name == "XOR": res = (val_src ^ val_key)
            elif op_name == "AND": res = (val_src & val_key)
            elif op_name == "OR":  res = (val_src | val_key)
            elif op_name == "NOT": res = (~val_src)
            elif op_name == "SUB": res = (val_src - val_key)
            elif op_name == "DIV": res = (val_src // val_key) if val_key != 0 else 0
            elif op_name == "MOD": res = (val_src % val_key) if val_key != 0 else 0
            # Shift/Rotate 연산은 64비트 마스킹 필요
            mask = (1 << 64) - 1
            shift = val_key & 0xFF
            if op_name == "SHL": res = (val_src << shift)
            elif op_name == "SHR": res = (val_src >> shift)
            elif op_name == "ROL": 
                res = ((val_src << shift) | (val_src >> (64 - shift)))
            elif op_name == "ROR":
                res = ((val_src >> shift) | (val_src << (64 - shift)))
            
            # 64비트 범위 제한
            res &= (2**64 - 1)
            
            # 결과 메모리에 쓰기 (다음 연산을 위해)
            state.memory.store(dst_ptr, state.solver.BVV(res, 64), endness='Iend_LE')
            
            # 강제 점프 (스택 실행 방지)
            state.regs.eip = return_addr
            
        else:
            # Helper Gate 등은 그냥 통과 (물리적으로 다음 retf 찾아서 점프)
            # (이전 턴의 로직 활용)
            current_ip = state.addr
            chunk = state.memory.load(current_ip + 1, 64)
            chunk_bytes = state.solver.eval(chunk, cast_to=bytes)
            offset = chunk_bytes.find(b'\xcb') # retf
            if offset != -1:
                state.regs.eip = current_ip + 1 + offset + 1
            else:
                state.regs.eip = target_addr # Fallback

    # Hooking
    gate_hooks = [
        0x8049cc8, 0x8049cff, 0x8049e01, 0x8049e38, 
        0x8049f06, 0x8049f3d, 0x8049fdb, 0x804a012,
        0x804a0b0, 0x804a0e7, 0x804a235, 0x804a26c,
        0x804a34c, 0x804a383, 0x804a463, 0x804a49a,
        0x804a557, 0x804a58e, 0x804a676, 0x804a6ad,
        0x804a77b, 0x804a7b2, 0x804a880, 0x804a8b7,
        0x804a985, 0x804a9bc, 0x804aabf, 0x804aaf5,
        0x804abc3, 0x804abfb, 0x804ad27, 0x804ad5e
    ]
    for addr in gate_hooks:
        project.hook(addr, hook_tracer, length=1)

    # 실행 설정 (구체적 값 입력)
    state = project.factory.blank_state(addr=0x08049574)
    state.regs.ebp = 0xffffd000
    state.regs.esp = 0xffffb000
    
    # Trace용 Dummy Input (모두 0)
    input_addr = 0xffffd000 - 0x2c0
    state.memory.store(input_addr, b'\x00' * 64)
    
    sm = project.factory.simulation_manager(state)
    # 비교 루프 끝나는 지점까지 실행
    sm.explore(find=0x804ae0a)
    
    print(f"[*] Trace Complete. Recorded {len(trace_log)} ALU operations.")
    return input_addr

# -----------------------------------------------------------
# [3] Solve 단계: Z3 Solver로 역연산
# -----------------------------------------------------------
def solve_z3(input_base_addr):
    print("[*] Phase 2: Solving constraints with Z3...")
    
    s = Solver()
    
    # 1. Flag 변수 생성 (8비트 64개)
    flag_vars = [BitVec(f'f_{i}', 8) for i in range(64)]
    
    # 2. 메모리 맵 (주소 -> Z3 Expression)
    # 초기 메모리 상태: 입력 버퍼는 Flag 변수로, 나머지는 0(또는 상수)으로 가정
    memory_map = {}
    
    # 입력 주소 바인딩
    for i in range(64):
        memory_map[input_base_addr + i] = flag_vars[i]
        # ASCII 범위 제약 조건 추가
        s.add(flag_vars[i] >= 0x20, flag_vars[i] <= 0x7E)

    # 3. 헬퍼 함수: 메모리 로드/스토어
    def get_mem_expr(addr):
        # 64비트(8바이트) 로드 (Little Endian)
        bytes_list = []
        for i in range(8):
            a = addr + i
            if a not in memory_map:
                # Trace 시점의 상수가 필요하면 angr에서 읽어야 하지만,
                # 이 문제 패턴상 보통 상수는 코드에서 직접 대입하거나 
                # Key 배열(고정)에서 옴. 여기선 0 또는 Trace 당시의 Concrete값이라 가정.
                # 편의상, 없는 주소는 Trace 당시 값이 '상수'였다고 가정하고 0 처리
                # (만약 답이 안 나오면 이 부분은 angr memory에서 덤프해야 함)
                memory_map[a] = BitVecVal(0, 8) 
            bytes_list.append(memory_map[a])
        
        # Little Endian -> Concat(Byte7, Byte6 ... Byte0)
        return Concat(bytes_list[::-1])

    def set_mem_expr(addr, expr):
        # 64비트 표현식을 8비트 조각으로 쪼개서 저장
        for i in range(8):
            # Extract(high, low)
            piece = Extract(i*8 + 7, i*8, expr)
            memory_map[addr + i] = piece

    # 4. Trace Replay
    for step in trace_log:
        op = step['op']
        dst = step['dst']
        src = step['src']
        key = step['key']
        
        # Operand를 Z3 식으로 변환
        val_src = get_mem_expr(src)
        val_key = get_mem_expr(key)
        
        # 연산 식 구성
        res = val_src # Default
        
        if op == "MOV": res = val_src
        elif op == "ADD": res = val_src + val_key
        elif op == "SUB": res = val_src - val_key
        elif op == "MUL": res = val_src * val_key
        elif op == "XOR": res = val_src ^ val_key
        elif op == "AND": res = val_src & val_key
        elif op == "OR":  res = val_src | val_key
        elif op == "NOT": res = ~val_src
        
        # Shift 계열 (하위 6비트만 사용)
        shift_amt = ZeroExt(64-8, Extract(7, 0, val_key))
        if op == "SHL": res = val_src << shift_amt
        elif op == "SHR": res = LShR(val_src, shift_amt)
        elif op == "ROL": res = RotateLeft(val_src, shift_amt)
        elif op == "ROR": res = RotateRight(val_src, shift_amt)
        
        # 결과를 가상의 메모리에 업데이트
        set_mem_expr(dst, res)

    # 5. 최종 Output 제약 조건 연결
    # 마지막 연산이 끝나면 Output Buffer(ebp-0x800)에 결과가 있음.
    # trace_all.csv 로직상 마지막 esi(쓰기 주소)들이 결과값임.
    # 하지만 더 간단히: Trace상 마지막에 쓰여진 영역이 결과일 것임.
    # Output Buffer Addr: Input(ebp-0x2c0) 보다 아래인 ebp-0x800
    # -> Input Base - 0x540 위치
    
    output_base = input_base_addr - 0x540
    print(f"[*] Constraining output at {hex(output_base)}")
    
    # TARGET_BYTES와 매칭
    # 64바이트 (8바이트 * 8개 청크)
    for i in range(0, 64, 8):
        current_mem = get_mem_expr(output_base + i)
        target_chunk = TARGET_BYTES[i:i+8]
        # bytes -> int (Little Endian)
        target_val = int.from_bytes(target_chunk, 'little')
        
        s.add(current_mem == target_val)

    # 6. Check
    print("[*] Checking model...")
    if s.check() == sat:
        m = s.model()
        # 플래그 복원
        result_bytes = []
        for i in range(64):
            val = m.eval(flag_vars[i]).as_long()
            result_bytes.append(val)
        
        flag = bytes(result_bytes)
        print(f"\n[+] Flag: {flag.decode('utf-8', errors='ignore')}")
    else:
        print("[-] UNSAT: Constraints are inconsistent. Check Opcode Map or Input Base.")

if __name__ == "__main__":
    # 1. Trace 실행
    input_base = run_tracer()
    
    # 2. Z3 풀이
    solve_z3(input_base)