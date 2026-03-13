import angr
import claripy

def main():
    print("[*] Loading binary into Angr...")
    project = angr.Project('./dhcc', auto_load_libs=False)

    # 플래그 길이 추정 (대충 30자부터 시작했음)
    FLAG_LEN = 30
    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(FLAG_LEN)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

    # 프로그램 초기화
    state = project.factory.full_init_state(
        args=['./dhcc'],
        stdin=flag
    )

    # 조건 설정
    # 1. 플래그 형식 'DH{'
    state.solver.add(flag_chars[0] == b'D'[0])
    state.solver.add(flag_chars[1] == b'H'[0])
    state.solver.add(flag_chars[2] == b'{'[0])

    # 2. 마지막은 '}'
    state.solver.add(flag_chars[-1] == b'}'[0])

    # 3. 아스키코드 범위
    for i in range(3, FLAG_LEN - 1):
        state.solver.add(flag_chars[i] >= 0x20)
        state.solver.add(flag_chars[i] <= 0x7e)

    simgr = project.factory.simulation_manager(state)

    # 성공 조건: fd 1 (stdout)에 "Correct!"가 출력
    def is_successful(state):
        return b"Correct!" in state.posix.dumps(1)

    # 실패(회피) 조건: fd 2 (stderr)에 "Wrong!"이나 에러 메시지가 출력
    def should_abort(state):
        stderr_output = state.posix.dumps(2)
        return b"Wrong!" in stderr_output or b"error" in stderr_output

    print("[*] Starting symbolic execution. This might take a few minutes...")
    simgr.explore(find=is_successful, avoid=should_abort)

    if simgr.found:
        found_state = simgr.found[0]
        print("\n[+] Success! Flag found:")
        print(found_state.posix.dumps(0).decode('utf-8'))
    else:
        print("\n[-] fail, change FLAG_LEN")

if __name__ == '__main__':
    main()
