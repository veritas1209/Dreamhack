#!/usr/bin/env python3
"""
CTF XOR Disaster Solver - Linear Algebra Approach (Fixed)
GF(2) 상에서 선형 방정식을 풀어 해결
"""

import numpy as np

try:
    from disaster import *
    DISASTER_IMPORTED = True
except ImportError:
    DISASTER_IMPORTED = False
    print("[!] 경고: disaster.py를 찾을 수 없습니다.")


def gauss_elimination_gf2(A, b):
    """
    GF(2) 상에서 Ax = b를 푸는 가우스 소거법
    
    Returns:
        solution vector x (numpy array)
    """
    n = len(b)
    m = A.shape[1]
    
    # 확대 행렬 생성 [A | b]
    M = np.column_stack([A.copy(), b.copy().reshape(-1, 1)])
    M = M.astype(np.uint8)
    
    print("[*] 전방 소거(Forward Elimination) 중...")
    
    # Forward elimination with partial pivoting
    current_row = 0
    pivot_cols = []
    
    for col in range(m):
        # Pivot 찾기
        pivot = -1
        for row in range(current_row, n):
            if M[row, col] == 1:
                pivot = row
                break
        
        if pivot == -1:
            continue
        
        pivot_cols.append(col)
        
        # Swap rows
        if pivot != current_row:
            M[[current_row, pivot]] = M[[pivot, current_row]]
        
        # Eliminate
        for row in range(n):
            if row != current_row and M[row, col] == 1:
                M[row] = (M[row] + M[current_row]) % 2
        
        current_row += 1
        
        if current_row % 32 == 0:
            print(f"    진행: {current_row}/{n} 행 처리됨")
    
    print(f"[*] {len(pivot_cols)}개의 pivot 열 발견")
    print("[*] 후방 대입(Back Substitution) 중...")
    
    # 해 추출
    x = np.zeros(m, dtype=np.uint8)
    
    # Pivot 열에 대해 해 설정
    for i, col in enumerate(pivot_cols):
        if i < len(M):
            x[col] = M[i, -1]
    
    return x


def solve_with_linear_algebra():
    """
    선형 대수학을 이용한 풀이
    """
    if not DISASTER_IMPORTED:
        print("[-] disaster.py를 import할 수 없습니다.")
        return None
    
    print("[*] 선형 대수 방법 사용 중...")
    print("[*] GF(2) 상에서 256x256 행렬 생성 중...\n")
    
    # 256x256 행렬 A와 256x1 벡터 b 생성 (GF(2))
    A = np.zeros((256, 256), dtype=np.uint8)
    b = np.zeros(256, dtype=np.uint8)
    
    # 목표 값들
    targets = [246, 44, 115, 230, 101, 35, 204, 151, 20, 200, 
               112, 111, 231, 74, 41, 189, 95, 22, 222, 90, 
               58, 130, 0, 172, 1, 236, 89, 243, 80, 113, 242, 112]
    
    print("[단계 1] 각 함수의 선형 변환 행렬 계산")
    print("=" * 60)
    
    # 각 함수에 대해 행렬 생성
    for func_idx in range(32):
        func_name = f'xor{func_idx}'
        if func_name not in globals():
            print(f"[-] 함수 {func_name}을 찾을 수 없습니다.")
            return None
        
        func = globals()[func_name]
        target = targets[func_idx]
        
        print(f"[{func_idx+1}/32] {func_name} 처리 중...", end=' ', flush=True)
        
        # 상수항 계산 (입력이 0일 때의 출력)
        const_output = func(0)
        
        # 각 입력 비트 위치에 대해 함수의 선형 변환 계산
        for bit_pos in range(256):
            # bit_pos 번째 비트만 1로 설정한 입력
            test_input = 1 << bit_pos
            
            # 함수 실행
            result = func(test_input)
            
            # XOR해서 상수항 제거 (선형성: f(x) = f(x) XOR f(0))
            linear_result = result ^ const_output
            
            # linear_result의 각 비트를 행렬에 기록
            for out_bit in range(8):
                row_idx = func_idx * 8 + out_bit
                if linear_result & (1 << out_bit):
                    A[row_idx, bit_pos] = 1
        
        # b 벡터 설정: target XOR const
        target_adjusted = target ^ const_output
        for out_bit in range(8):
            row_idx = func_idx * 8 + out_bit
            if target_adjusted & (1 << out_bit):
                b[row_idx] = 1
        
        print("완료")
    
    print(f"\n[단계 2] 연립방정식 풀이")
    print("=" * 60)
    print(f"[*] 행렬 크기: {A.shape}")
    print(f"[*] 방정식 개수: {len(b)}")
    print(f"[*] 변수 개수: {A.shape[1]}")
    
    # 행렬 rank 확인
    rank = np.linalg.matrix_rank(A % 2)
    print(f"[*] 행렬 rank: {rank}")
    print()
    
    try:
        # GF(2) 상에서 Ax = b 풀기
        solution = gauss_elimination_gf2(A, b)
        
        print("\n[*] 해 검증 중...")
        # Ax를 계산하여 b와 비교
        result = np.zeros(256, dtype=np.uint8)
        for i in range(256):
            for j in range(256):
                result[i] ^= (A[i, j] & solution[j])
        
        mismatches = np.sum(result != b)
        if mismatches == 0:
            print("[+] 검증 성공: Ax = b")
        else:
            print(f"[!] 경고: {mismatches}개 불일치, 하지만 시도해봅니다...")
        
        # 비트 벡터를 정수로 변환
        flag_value = 0
        for i in range(256):
            if solution[i] == 1:
                flag_value |= (1 << i)
        
        flag = f"DH{{{flag_value:064x}}}"
        print(f"\n[+] 플래그 생성 완료!")
        return flag
        
    except Exception as e:
        print(f"[-] 해를 찾을 수 없습니다: {e}")
        import traceback
        traceback.print_exc()
        return None


def verify_flag(flag):
    """플래그 검증"""
    if not DISASTER_IMPORTED:
        print("[!] disaster.py가 없어서 검증할 수 없습니다.")
        return False
    
    print(f"\n[단계 3] 최종 검증")
    print("=" * 60)
    print(f"[*] 플래그: {flag}")
    
    try:
        # 플래그 형식 확인
        if not (len(flag) == 68 and flag[:3] == 'DH{' and flag[-1] == '}'):
            print("[-] 플래그 형식이 올바르지 않습니다.")
            return False
        
        v = int(flag[3:-1], 16)
        print(f"[*] 정수 값: {v}")
        print(f"[*] 16진수: {v:064x}")
        print()
        
        targets = [246, 44, 115, 230, 101, 35, 204, 151, 20, 200, 
                   112, 111, 231, 74, 41, 189, 95, 22, 222, 90, 
                   58, 130, 0, 172, 1, 236, 89, 243, 80, 113, 242, 112]
        
        all_correct = True
        failed_checks = []
        
        print("[*] 32개 함수 검증 중...")
        for i, target in enumerate(targets):
            func_name = f'xor{i}'
            if func_name in globals():
                func = globals()[func_name]
                result = func(v)
                
                if result == target:
                    status = "✓"
                else:
                    status = "✗"
                    failed_checks.append((i, result, target))
                    all_correct = False
                
                # 실패한 것만 출력
                if not all_correct and len(failed_checks) <= 5:
                    print(f"    {func_name}: {result} == {target} {status}")
        
        print()
        if all_correct:
            print("[+] ★★★ 모든 검증 통과! 플래그가 정확합니다! ★★★")
            return True
        else:
            print(f"[-] {len(failed_checks)}개의 검증 실패")
            if len(failed_checks) <= 10:
                for i, result, target in failed_checks:
                    print(f"    xor{i}: {result} != {target}")
            return False
            
    except Exception as e:
        print(f"[!] 검증 중 오류: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """메인 함수"""
    print("=" * 60)
    print("CTF XOR Disaster Solver")
    print("Linear Algebra Method (Fixed)")
    print("=" * 60)
    print()
    print("[*] 원리: GF(2) 상에서 256x256 선형 방정식 풀이")
    print("[*] 모든 XOR/shift 연산은 선형 → Ax=b로 변환 가능")
    print()
    
    if not DISASTER_IMPORTED:
        print("[!] disaster.py 파일을 찾을 수 없습니다.")
        print("[!] disaster.py를 이 스크립트와 같은 디렉토리에 두세요.")
        return
    
    # 선형 대수 방법 시도
    flag = solve_with_linear_algebra()
    
    if flag:
        print(f"\n{'=' * 60}")
        print(f"최종 플래그: {flag}")
        print(f"{'=' * 60}")
        
        # 검증
        if verify_flag(flag):
            print(f"\n[+] 성공! 플래그를 복사하세요: {flag}")
        else:
            print("\n[-] 검증 실패. 다른 접근이 필요할 수 있습니다.")
    else:
        print("\n[-] 플래그를 찾을 수 없습니다.")


if __name__ == "__main__":
    main()