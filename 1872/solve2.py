import angr
import claripy
import sys

def solve():
    print("[*] Loading binary (Default Mode)...")
    # 최신 angr는 기본적으로 동적 실행 시 변경된 메모리를 반영합니다.
    p = angr.Project("./tmp", auto_load_libs=False)

    # 1. 플래그 심볼릭 변수 (64바이트)
    flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(64)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

    # 2. 초기 상태 설정
    # [핵심] 문제의 옵션들을 싹 다 뺐습니다.
    # 기본적인 LAZY_SOLVES만 남겨서 연산 효율만 챙깁니다.
    state = p.factory.full_init_state(
        args=["./tmp"],
        stdin=flag,
        add_options={
            angr.options.LAZY_SOLVES, 
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
        }
    )

    # 3. 제약 조건 (Printable ASCII)
    print("[*] Constraining input to printable ASCII...")
    for k in flag_chars:
        state.solver.add(k >= 0x20)
        state.solver.add(k <= 0x7E)

    # 4. 시뮬레이션 매니저 (순정)
    simgr = p.factory.simulation_manager(state)

    print("[*] Starting symbolic execution...")

    # 5. 탐색 조건
    def is_successful(state):
        stdout_output = state.posix.dumps(1)
        return b"Correct" in stdout_output or b"Congratulation" in stdout_output

    def is_failed(state):
        stdout_output = state.posix.dumps(1)
        return b"Wrong" in stdout_output

    # 6. 탐색 시작
    simgr.explore(find=is_successful, avoid=is_failed)

    # 7. 결과
    if simgr.found:
        found_state = simgr.found[0]
        result = found_state.posix.dumps(0)
        print(f"\n[+] Flag Found: {result.strip().decode('latin-1')}")
    else:
        print("\n[-] Failed to find the flag.")
        if simgr.deadended:
             print(f"[*] Deadended paths: {len(simgr.deadended)}")

if __name__ == "__main__":
    solve()