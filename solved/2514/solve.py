import re
import z3
import sys

def parse_ghidra_dump_to_bytes(filepath):
    print(f"[*] 1. '{filepath}' 파일에서 원시 바이트(Raw Bytes) 데이터를 파싱합니다...")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] 오류: '{filepath}' 파일이 존재하지 않습니다. 디컴파일 텍스트를 이 파일명으로 저장해 주세요.")
        sys.exit(1)

    matrix_A_bytes = []
    vector_B_bytes = []
    recent_assignments = []
    
    # Ghidra 스택 할당 패턴 파싱 (16진수, 10진수, 음수 대응)
    assign_pattern = re.compile(r'local_[a-f0-9]+\s*=\s*(-?0x[a-f0-9]+|-?\d+);')
    call_pattern = re.compile(r'FUN_00105b4e\(&DAT_(0010f[a-f0-9]+),\s*&local_[a-f0-9]+,\s*(0x[a-f0-9]+|\d+)\)')

    for idx, line in enumerate(lines):
        match_assign = assign_pattern.search(line)
        if match_assign:
            val_str = match_assign.group(1)
            val = int(val_str, 16) if '0x' in val_str.lower() else int(val_str, 10)
            # 1바이트 크기 마스킹으로 음수/부호 정밀화
            recent_assignments.append(val & 0xFF)
            continue
            
        match_call = call_pattern.search(line)
        if match_call:
            addr_str = match_call.group(1)
            len_str = match_call.group(2)
            
            addr = int(addr_str, 16)
            length = int(len_str, 16) if '0x' in len_str.lower() else int(len_str, 10)
            
            # 스택 버퍼에서 지정된 길이만큼 바이트 슬라이싱
            byte_chunk = recent_assignments[-length:]
            
            # 주소 0x0010fd00 기준으로 행렬 A와 타겟 벡터 B 분리
            if addr < 0x0010fd00:
                matrix_A_bytes.append(byte_chunk)
            else:
                vector_B_bytes.append(byte_chunk)
            
            recent_assignments = []

    print(f"    [+] 파싱 완료 -> Matrix A 청크: {len(matrix_A_bytes)}개, Vector B 청크: {len(vector_B_bytes)}개")
    return matrix_A_bytes, vector_B_bytes

def bytes_to_base128_int(byte_list, endian='little'):
    """바이트 배열을 7비트(Base-128) 진법 기준의 정수로 변환합니다."""
    total = 0
    # 자릿수 방향성(Little/Big)에 따른 인덱스 처리
    chunks = byte_list if endian == 'little' else reversed(byte_list)
    for power, b in enumerate(chunks):
        total += b * (128 ** power)
    return total

def solve_linear_system(mat_A, vec_B, desc_info):
    """Z3 솔버를 이용하여 128진법 기반 연립방정식을 해결합니다."""
    solver = z3.Solver()
    
    # 미지수 X (각 청크는 5바이트 문자열이므로 오버플로우가 없는 무한 정밀도 정수 Int 사용)
    X = [z3.Int(f'x_{i}') for i in range(10)]
    
    # 제약 조건 1: 플래그의 각 5바이트 청크 범위 지정 (0 ~ 256^5 - 1)
    max_chunk_val = (256 ** 5) - 1
    for i in range(10):
        solver.add(X[i] >= 0)
        solver.add(X[i] <= max_chunk_val)
        
    # 제약 조건 2: 행렬 곱셈 연산식 추가 (A * X = B)
    for row in range(10):
        equation = sum([mat_A[row][col] * X[col] for col in range(10)])
        solver.add(equation == vec_B[row])
        
    # 디버깅: 솔버 내부 규칙 및 체크 상태 출력
    print(f"    [진행] 솔버 검증 중... ({desc_info})")
    
    if solver.check() == z3.sat:
        print(f"\n[+] ★★★ SAT 성립! 유효한 정수 해를 찾았습니다. (조합: {desc_info})")
        model = solver.model()
        
        final_flag = b""
        print("\n[*] --- 단계별 미지수(X) 복원 및 ASCII 디코딩 결과 ---")
        for i in range(10):
            val = model[X[i]].as_long()
            # 플래그 생성 시 대입 방향은 일반 문자열(Big Endian 256진수) 순서
            chunk_bytes = val.to_bytes(5, byteorder='big')
            print(f"    -> X[{i}] 값: {val:<15} | 16진수: 0x{val:010x} | 문자열 조각: {chunk_bytes}")
            final_flag += chunk_bytes
            
        print("\n" + "="*60)
        print(f" 🎉 성공적으로 복원된 플래그(FLAG):")
        print(f" {final_flag.decode('utf-8', errors='replace')}")
        print("="*60)
        return True
        
    return False

if __name__ == "__main__":
    print("="*60)
    print(" Mirage CTF Reversing - Base-128 Matrix Solver")
    print("="*60)
    
    # 1. 원시 바이트 데이터 로드
    matrix_A_bytes, vector_B_bytes = parse_ghidra_dump_to_bytes("2514/dump.txt")
    
    if len(matrix_A_bytes) != 100 or len(vector_B_bytes) != 10:
        print("[!] 에러: 파싱된 데이터 개수가 연립방정식 요건(100개/10개)을 충족하지 못합니다.")
        sys.exit(1)
        
    print("\n[*] 2. 7비트(Base-128) 진법 자릿수 변환 및 다중 루프 검증을 시작합니다.")
    print("    (Ghidra 스택 구조에 따른 모든 엔디안 및 행렬 전치 조합 탐색)")
    
    found_solution = False
    endian_options = ['little', 'big']
    
    # 데이터 영역의 바이트가 쌓인 방향성을 찾기 위한 8가지 브루트포스 교차 검증
    for a_end in endian_options:
        for b_end in endian_options:
            
            # 현재 엔디안 기준에 따라 바이트 배열을 128진수 거대 정수로 가중치 연산
            parsed_A_flat = [bytes_to_base128_int(chunk, endian=a_end) for chunk in matrix_A_bytes]
            parsed_B = [bytes_to_base128_int(chunk, endian=b_end) for chunk in vector_B_bytes]
            
            # 1D 평탄화 배열을 10x10 행렬 구조로 재구성
            mat_A_normal = [parsed_A_flat[i:i+10] for i in range(0, 100, 10)]
            
            # 디버깅 출력: 변환된 첫 번째 행과 결과값 매핑 상태 모니터링
            print(f"\n[트래킹] 테스트 중 -> A자릿수: {a_end.upper()}, B자릿수: {b_end.upper()}")
            print(f"    -> 샘플링 가중치 정수 A[0][0]: {mat_A_normal[0][0]}")
            print(f"    -> 샘플링 가중치 정수 B[0]   : {parsed_B[0]}")
            
            # Case 1: 일반적인 Row-major 구조 행렬곱 시도
            info_normal = f"A_Limb: {a_end}, B_Limb: {b_end}, 구조: Normal"
            if solve_linear_system(mat_A_normal, parsed_B, info_normal):
                found_solution = True
                break
                
            # Case 2: 메모리가 가로가 아닌 세로(Col-major)로 매핑되었을 가능성을 위한 전치 행렬(Transpose) 시도
            mat_A_transposed = [[mat_A_normal[r][c] for r in range(10)] for c in range(10)]
            info_trans = f"A_Limb: {a_end}, B_Limb: {b_end}, 구조: Transposed"
            if solve_linear_system(mat_A_transposed, parsed_B, info_trans):
                found_solution = True
                break
                
        if found_solution:
            break
            
    if not found_solution:
        print("\n" + "!"*60)
        print(" [-] 모든 128진수 변환 조합을 대입했으나 해를 찾지 못했습니다(UNSAT).")
        print("     Ghidra 텍스트 복사 시 local_ 변수의 누락이나 주소 누락이 없는지 다시 점검해 주세요.")
        print("!"*60)