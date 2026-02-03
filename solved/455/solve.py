import angr
import claripy
import sys

def solve():
    # 1. 바이너리 로드 (바이너리 파일명이 'nonsense'라고 가정)
    path_to_binary = "./nonsense" 
    project = angr.Project(path_to_binary, main_opts={'base_addr': 0x400000}, auto_load_libs=False)

    # 2. 플래그 길이 설정 (코드에서 0x30 == 48바이트 확인됨)
    flag_len = 0x30
    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(flag_len)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')]) # 끝에 개행 추가

    # 3. 초기 상태(State) 생성
    # argv[1]에 심볼릭 변수(우리가 찾을 값)를 넣어서 시작
    state = project.factory.full_init_state(
        args=[path_to_binary, flag],
        add_options=angr.options.unicorn_options
    )

    # 4. 플래그 제약 조건 추가 (출력 가능한 문자로 제한하면 속도 향상)
    for k in flag_chars:
        state.solver.add(k >= 0x20) # 스페이스바 이상
        state.solver.add(k <= 0x7e) # '~' 이하

    # 5. 시뮬레이션 매니저 생성
    simgr = project.factory.simulation_manager(state)

    # 6. 목표 주소 설정
    # Ghidra에서 확인한 주소를 넣어야 합니다.
    # 성공 주소: "wrong"을 출력하지 않고 return 0; 하는 부분 (FUN_00100b0a의 끝)
    # 실패 주소: "wrong"을 출력하는 부분 혹은 _exit(1) 호출 부분
    
    # 예시 주소 (실제 바이너리를 열어 주소를 확인하고 수정하세요!)
    # find_addr = 0x400XXX  # return 0; 직전
    # avoid_addr = [0x400YYY, 0x400ZZZ] # _exit(1) 혹은 printf("wrong")
    
    print("[*] Exploring...")
    
    # 7. 탐색 시작 (성공 주소를 찾을 때까지)
    # 'wrong' 문자열이 출력되는 것을 피하고 싶다면 아래와 같이 텍스트 기반 탐색도 가능합니다.
    simgr.explore(
        find=lambda s: b"wrong" not in s.posix.dumps(1) and s.addr == 0x400XXX (종료지점), 
        avoid=lambda s: b"wrong" in s.posix.dumps(1)
    )
    
    # 혹은 주소 기반 탐색 (가장 확실함)
    # simgr.explore(find=find_addr, avoid=avoid_addr)

    # 8. 결과 출력
    if simgr.found:
        found_state = simgr.found[0]
        # 찾은 상태에서 표준 입력/인자값 복원
        result = found_state.solver.eval(flag, cast_to=bytes)
        print(f"[+] Flag found: {result}")
    else:
        print("[-] Flag not found")

if __name__ == "__main__":
    solve()