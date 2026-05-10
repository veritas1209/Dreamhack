import sys
import struct
import z3
import angr
import claripy
from pwn import *

# 자잘한 경고문 및 로깅 숨김 처리
context.log_level = 'error'
import logging
logging.getLogger('angr').setLevel(logging.ERROR)

def main():
    print("[DEBUG] ⚔️ Z3 + angr 하이브리드 결전 병기 가동!")
    binary_path = "./chal"
    
    try:
        elf = ELF(binary_path)
        elf.address = 0x100000
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
        
    vm_code_va = 0x10b020
    target_data_va = 0x1459a0
    num_instructions = 10000
    instruction_size = 24
    
    raw_vm_code = elf.read(vm_code_va, num_instructions * instruction_size)
    instructions = []
    unique_opcodes = set()
    
    for i in range(num_instructions):
        chunk = raw_vm_code[i*24:(i+1)*24]
        p1, p2, p3 = struct.unpack('<QQQ', chunk)
        instructions.append((p1, p2, p3))
        unique_opcodes.add(p1)  # 중복 제거를 위한 Set
        
    target_bytes = elf.read(target_data_va, 64)
    print(f"[DEBUG] 명령어 로드 완료. 총 10,000개 중 고유(Unique) Opcode는 {len(unique_opcodes)}개입니다.")
    
    print("[DEBUG] 🧠 angr를 이용해 Opcode의 숨겨진 연산(Semantics)을 블랙박스 테스트합니다...")
    proj = angr.Project(binary_path, auto_load_libs=False)
    func_addr = proj.loader.main_object.min_addr + 0x1209
    
    opcode_to_op = {}
    
    # Unicorn 엔진을 사용하여 단일 분기 테스트 속도를 극한으로 끌어올림
    opt = {angr.options.UNICORN}
    
    for idx, opcode in enumerate(unique_opcodes):
        # FUN_00101209(opcode, 0x40000, 0x40001) 형태로 호출
        state = proj.factory.call_state(func_addr, opcode, 0x40000, 0x40001, add_options=opt)
        
        # 더미 데이터 A(0x33), B(0x55) 세팅
        state.memory.store(0x40000, claripy.BVV(0x33, 8))
        state.memory.store(0x40001, claripy.BVV(0x55, 8))
        
        simgr = proj.factory.simulation_manager(state)
        simgr.run()
        
        if not simgr.deadended:
            print(f"[ERROR] Opcode {hex(opcode)} 분석 실패 (막다른 길 도달 X)")
            sys.exit(1)
            
        res_state = simgr.deadended[0]
        val = res_state.solver.eval(res_state.memory.load(0x40000, 1))
        
        # 테스트 결과에 따른 연산자 매핑
        if val == 0x66: op = 'XOR'        # 0x33 ^ 0x55 = 0x66
        elif val == 0x88: op = 'ADD'      # 0x33 + 0x55 = 0x88
        elif val == 0xde: op = 'SUB'      # 0x33 - 0x55 = -0x22 (0xDE)
        elif val == 0x22: op = 'SUB_REV'  # 0x55 - 0x33 = 0x22
        elif val == 0x77: op = 'OR'       # 0x33 | 0x55 = 0x77
        elif val == 0x11: op = 'AND'      # 0x33 & 0x55 = 0x11
        else: op = f'UNKNOWN_{hex(val)}'
        
        opcode_to_op[opcode] = op
        
        if (idx + 1) % 50 == 0 or (idx + 1) == len(unique_opcodes):
            print(f"  -> 분석 진행률: {idx+1} / {len(unique_opcodes)} 완료")

    print("\n[DEBUG] 🧩 Z3 솔버(Solver)를 생성하고 10,000개의 연산을 수식으로 조립합니다...")
    solver = z3.Solver()
    
    # 64바이트의 플래그 배열 생성
    flag = [z3.BitVec(f'flag_{i}', 8) for i in range(64)]
    sim_flag = flag[:]
    
    for i, (opcode, dest_off, src_off) in enumerate(instructions):
        op = opcode_to_op[opcode]
        d = int(dest_off)
        s = int(src_off)
        
        if op == 'XOR':
            sim_flag[d] = sim_flag[d] ^ sim_flag[s]
        elif op == 'ADD':
            sim_flag[d] = sim_flag[d] + sim_flag[s]
        elif op == 'SUB':
            sim_flag[d] = sim_flag[d] - sim_flag[s]
        elif op == 'SUB_REV':
            sim_flag[d] = sim_flag[s] - sim_flag[d]
        else:
            print(f"[ERROR] 처리할 수 없는 비정상 연산자: {op} (Opcode: {hex(opcode)})")
            sys.exit(1)
            
    print("[DEBUG] 🎯 64바이트 타겟 데이터와 일치하도록 수학적 제약 조건 주입 중...")
    for i in range(64):
        solver.add(sim_flag[i] == target_bytes[i])
        
    # 출력 가능 ASCII 및 플래그 포맷 제약
    solver.add(flag[0] == ord('D'))
    solver.add(flag[1] == ord('H'))
    solver.add(flag[2] == ord('{'))
    solver.add(flag[63] == ord('}'))
    
    print("[DEBUG] ⏳ Z3 연산 시작! (방대한 수식 최적화로 인해 잠시만 기다려주세요)")
    if solver.check() == z3.sat:
        model = solver.model()
        result = "".join([chr(model[flag[i]].as_long()) for i in range(64)])
        print("=" * 60)
        print(f"🎉 성공! Flag: {result}")
        print("=" * 60)
    else:
        print("[ERROR] Z3가 조건을 풀지 못했습니다. (UNSAT)")

if __name__ == "__main__":
    main()