import angr
import claripy
import logging

# 불필요한 경고 끄기
logging.getLogger('angr').setLevel(logging.CRITICAL)

def solve():
    binary_path = './prob'
    print(f"[*] Loading binary: {binary_path}")
    project = angr.Project(binary_path, auto_load_libs=False)

    # 1. 64비트 ALU 연산 맵핑
    alu_ops = {
        0x8049186: "MOV", 0x80491db: "MUL", 0x8049223: "XOR",
        0x8049267: "AND", 0x80492a8: "OR",  0x8049310: "NOT",
        0x804933a: "SHL", 0x8049376: "SHR", 0x80493b2: "ROL",
        0x80493ee: "ROR", 0x804942a: "DIV", 0x804946a: "MOD",
        0x80494a0: "SUB",
    }

    # 2. 안전한 후킹 함수
    def hook_heavens_gate_safe(state):
        # 스택에서 64비트 타겟 주소 가져오기
        target_addr_bv = state.memory.load(state.regs.esp, 4, endness='Iend_LE')
        try:
            target_addr = state.solver.eval(target_addr_bv)
        except:
            # 주소 해석 실패 시 그냥 리턴 (angr가 알아서 하도록)
            return

        # retf 시뮬레이션 (스택에서 IP, CS pop -> ESP + 8)
        state.regs.esp += 8

        # 타겟이 우리가 아는 ALU 연산인지 확인
        op_name = alu_ops.get(target_addr)

        if op_name:
            # [Case A] ALU 연산임 -> 파이썬으로 계산하고 강제 복귀
            
            # 인자 로드 (32비트 레지스터)
            src_ptr = state.regs.edx
            key_ptr = state.regs.ecx
            dst_ptr = state.regs.esi
            return_addr = state.regs.edi  # ★ ALU 연산은 EDI에 복귀 주소가 있음

            # 값 로드
            val_src = state.memory.load(src_ptr, 8, endness='Iend_LE')
            val_key = state.memory.load(key_ptr, 8, endness='Iend_LE')
            
            # 연산 수행
            res = val_src
            if op_name == "MOV": res = val_src
            elif op_name == "MUL": res = val_src * val_key
            elif op_name == "XOR": res = val_src ^ val_key
            elif op_name == "AND": res = val_src & val_key
            elif op_name == "OR":  res = val_src | val_key
            elif op_name == "NOT": res = ~val_src
            elif op_name == "SHL": res = val_src << val_key[7:0].zero_extend(56)
            elif op_name == "SHR": res = claripy.LShR(val_src, val_key[7:0].zero_extend(56))
            elif op_name == "ROL": res = claripy.RotateLeft(val_src, val_key[7:0].zero_extend(56))
            elif op_name == "ROR": res = claripy.RotateRight(val_src, val_key[7:0].zero_extend(56))
            elif op_name == "DIV": res = val_src / val_key
            elif op_name == "MOD": res = val_src % val_key
            elif op_name == "SUB": res = val_src - val_key
            
            # 결과 저장
            state.memory.store(dst_ptr, res, endness='Iend_LE')
            
            # 32비트 코드로 강제 점프 (64비트 코드 실행 생략)
            state.regs.eip = return_addr
            
        else:
            # [Case B] 모르는 놈(Helper Gate)임 -> 그냥 실행시킴
            # 64비트 코드로 점프하지만, 보통 NOP/POP 등 단순 명령어라 
            # angr가 32비트 모드에서도 얼추 처리해냄.
            # 스택 주소로 점프하는 경우(Trampoline)도 여기서 처리됨.
            state.regs.eip = target_addr

    # 3. Hooking
    # 발견된 모든 Heaven's Gate 지점
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
    
    print(f"[*] Hooking {len(gate_hooks)} gates...")
    for addr in gate_hooks:
        project.hook(addr, hook_heavens_gate_safe, length=1)

    # 4. State 및 탐색
    state = project.factory.blank_state(addr=0x08049574)
    state.regs.ebp = 0xffffd000
    state.regs.esp = 0xffffb000

    flag = claripy.BVS('flag', 64 * 8)
    state.memory.store(state.regs.ebp - 0x2c0, flag)

    sm = project.factory.simulation_manager(state, veritesting=True)
    
    print("[*] Exploring...")
    sm.explore(find=0x804ae0a)

    if sm.found:
        print("\n[!] Solved!")
        flag_str = sm.found[0].solver.eval(flag, cast_to=bytes)
        try:
            print(f"[+] Flag: {flag_str.decode('utf-8')}")
        except:
            print(f"[+] Flag (Raw): {flag_str}")
    else:
        print("[-] Not found yet.")
        if sm.errored:
            print(f"[-] Error: {sm.errored[0]}")

if __name__ == "__main__":
    solve()