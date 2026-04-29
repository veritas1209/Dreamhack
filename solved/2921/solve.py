import angr
import claripy
import sys

# 1. 플래그 32바이트 생성 (종료 문자 \x00 포함, 총 33바이트)
# strcspn 우회를 위해 \n은 넣지 않음
flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(32)]
flag_ast = claripy.Concat(*flag_chars + [claripy.BVV(b'\x00')])

# --- [마법의 SimProcedure 후킹 클래스들] ---
# 1. fgets 우회: 표준 입력 대기 중단 및 메모리에 심볼릭 변수 강제 삽입
class FgetsBypass(angr.SimProcedure):
    def run(self, s, size, stream):
        print(f"  [+] fgets 후킹 성공! 버퍼(주소: {hex(self.state.solver.eval(s))})에 심볼릭 플래그 강제 주입.")
        self.state.memory.store(s, flag_ast)
        return s

# 2. strcspn 우회: 심볼릭 문자열 연산 폭주 방지
class StrcspnBypass(angr.SimProcedure):
    def run(self, s, reject):
        print("  [+] strcspn 후킹 성공! 개행문자 탐색 건너뛰고 길이 32 반환.")
        return 32

# 3. strlen 우회: check 함수 내부의 strlen 연산 폭주 방지
class StrlenBypass(angr.SimProcedure):
    def run(self, s):
        print("  [+] strlen 후킹 성공! 길이 32 반환.")
        return 32
# ----------------------------------------

def solve(binary_path="./mirage"):
    print("[*] 1. 바이너리 로드 시작...")
    proj = angr.Project(binary_path, auto_load_libs=False)

    print("[*] 2. 외부 C 함수 후킹(Hooking) 적용 중...")
    # 바이너리의 PLT/GOT 심볼을 찾아 우리가 만든 클래스로 바꿔치기함
    proj.hook_symbol('fgets', FgetsBypass())
    proj.hook_symbol('strcspn', StrcspnBypass())
    proj.hook_symbol('strlen', StrlenBypass())

    print("[*] 3. 상태(State) 생성 및 제약 조건 추가...")
    state_options = {
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
    }
    
    # stdin 인자를 아예 제거. fgets를 후킹했으므로 더 이상 필요 없음!
    state = proj.factory.entry_state(args=[binary_path], add_options=state_options)

    # 기본 포맷 제약 (DH{...})
    state.solver.add(flag_chars[0] == ord('D'))
    state.solver.add(flag_chars[1] == ord('H'))
    state.solver.add(flag_chars[2] == ord('{'))
    state.solver.add(flag_chars[31] == ord('}'))

    # 내부 문자열은 출력 가능한 ASCII 범위로 제한하고, 개행문자가 들어가지 않도록 제약
    for i in range(3, 31):
        state.solver.add(flag_chars[i] >= 0x20)
        state.solver.add(flag_chars[i] <= 0x7e)
        state.solver.add(flag_chars[i] != ord('\n')) 

    print("[*] 4. 시뮬레이션 매니저(SimulationManager) 초기화...")
    simgr = proj.factory.simulation_manager(state)

    print("\n" + "="*50)
    print("[*] 5. 심볼릭 실행 탐색 시작! (이번엔 끝까지 갈 거야)")
    print("="*50)
    
    step_count = 0
    while simgr.active:
        # 터미널 창 도배를 막기 위해 활성 상태 개수만 출력
        if step_count % 10 == 0:
            print(f"[Step {step_count:04d}] 현재 활성화된 분기(Active) 개수: {len(simgr.active)}")
        
        simgr.step()
        
        for st in simgr.active[:]:
            stdout_data = st.posix.dumps(sys.stdout.fileno())
            
            if b"Correct!" in stdout_data:
                print(f"\n[!] 🎉 'Correct!' 출력 경로 발견! (주소: {hex(st.addr)})")
                simgr.move('active', 'found', lambda s: s == st)
            elif b"Wrong" in stdout_data:
                simgr.move('active', 'deadended', lambda s: s == st)
                
        if 'found' in simgr.stashes and len(simgr.stashes['found']) > 0:
            break
            
        if simgr.errored:
            print(f"\n  [!] 에러 발생 경로 감지: {len(simgr.errored)}개")
            simgr.drop(stash='errored')
            
        step_count += 1

    print("\n" + "="*50)
    if 'found' in simgr.stashes and len(simgr.stashes['found']) > 0:
        found_state = simgr.found[0]
        flag = found_state.solver.eval(flag_ast, cast_to=bytes)
        final_flag = flag.decode('utf-8', errors='ignore').strip('\x00')
        print(f"\n[+] 🚩 복구된 플래그: {final_flag}\n")
    else:
        print("\n[-] ❌ 'Correct!'를 출력하는 경로를 찾지 못했어.")

if __name__ == "__main__":
    solve("./mirage")