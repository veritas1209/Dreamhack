import angr
import claripy

def solve():
    print("[*] Angr 엔진 구동 시작... (시간이 조금 걸릴 수 있습니다!)")
    
    # 1. 바이너리 로드 (메모리 베이스 주소 고정, 외부 라이브러리 해석 안 함)
    proj = angr.Project('./specimen_braid_collapse.exe', main_opts={'base_addr': 0x140000000}, auto_load_libs=False)

    # 2. 심볼릭 입력값 정의 (형식: XXX-XXX-XXXXXXXX-XX-XXXXXX + \n)
    # 총 26글자 + 엔터(\n) = 27바이트
    sym_input = claripy.BVS('sym_input', 27 * 8)
    
    # 3. 상태(State) 생성
    state = proj.factory.entry_state(stdin=sym_input)

    # 🔥 [핵심 픽스] 미초기화 메모리/레지스터 에러 방지 옵션!
    # 이 옵션이 없으면 윈도우 바이너리 특성상 쓰레기값을 읽다가 경로를 잃어버립니다.
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    # 4. 연산 속도 최적화를 위한 빡빡한 제약 조건(Constraints) 추가
    # 하이픈(-) 및 엔터(\n) 위치 완벽 고정
    state.solver.add(sym_input.get_byte(3) == ord('-'))
    state.solver.add(sym_input.get_byte(7) == ord('-'))
    state.solver.add(sym_input.get_byte(16) == ord('-'))
    state.solver.add(sym_input.get_byte(19) == ord('-'))
    state.solver.add(sym_input.get_byte(26) == ord('\n'))

    # 각 구역별 허용된 문자셋 정의
    base32_chars = [ord(c) for c in "QWERTYUIOPASDFGHJKLZXCVBNM234567"]
    hex_chars = [ord(c) for c in "0123456789ABCDEF"]
    roman_chars = [ord('I'), ord('V'), ord('X')]
    digit_chars = [ord(c) for c in "0123456789"]

    # 1구역: 3글자 (Base32)
    for i in range(0, 3):
        state.solver.add(claripy.Or(*[sym_input.get_byte(i) == c for c in base32_chars]))
    
    # 2구역: 3글자 (숫자만)
    for i in range(4, 7):
        state.solver.add(claripy.Or(*[sym_input.get_byte(i) == c for c in digit_chars]))
    
    # 3구역: 8글자 (16진수 대문자)
    for i in range(8, 16):
        state.solver.add(claripy.Or(*[sym_input.get_byte(i) == c for c in hex_chars]))
    
    # 4구역: 2글자 (로마자 기호 I, V, X)
    for i in range(17, 19):
        state.solver.add(claripy.Or(*[sym_input.get_byte(i) == c for c in roman_chars]))
    
    # 5구역: 6글자 (Base32)
    for i in range(20, 26):
        state.solver.add(claripy.Or(*[sym_input.get_byte(i) == c for c in base32_chars]))

    # 5. 시뮬레이션 매니저 생성
    simgr = proj.factory.simulation_manager(state)

    # 6. 목적지 및 회피 지점 설정 (디버거에서 찾았던 그 주소들입니다!)
    FIND_ADDR = 0x140016A84   # "collapse accepted" 출력 지점
    AVOID_ADDR = 0x140016B2E  # "collapse rejected" 출력 지점

    print("[*] 모든 조건을 장전했습니다. 최적의 경로 탐색 중... 🚀")
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

    # 7. 결과 출력
    if simgr.found:
        found_state = simgr.found[0]
        # Angr가 찾아낸 0번째 표준 입력(stdin) 데이터 덤프
        flag = found_state.posix.dumps(0)
        print("\n==============================================")
        print("[+] 뚫었습니다! 진(眞) 마스터 키 :", flag.decode('utf-8', errors='ignore').strip())
        print("==============================================")
        print("[!] 이 키를 복사해서 순정 실행 파일 프롬프트에 붙여넣으세요!")
    else:
        print("\n[-] 경로를 찾지 못했습니다... (조건이 너무 빡빡하거나 로직 우회가 필요합니다)")

if __name__ == '__main__':
    solve()