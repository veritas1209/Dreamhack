import subprocess
import itertools
import sys
import os

def solve_final_puzzle():
    print("[-] 히다토 퍼즐 브루트포스 시작 (Max 40,320 시도)...")

    # 1. 메모리 덤프에서 복원한 225바이트 템플릿
    # (사용자님의 덤프 데이터를 기반으로 재구성했습니다)
    # 0x5cc700 ~ 0x5cca00
    
    # 기본적으로 1(벽)로 채움
    board = [1] * 225
    
    # 덤프된 데이터 매핑 (8바이트 정수 -> 1바이트로 압축)
    # 0x01은 벽, 0x00은 빈칸, 나머지는 힌트
    
    # Row 0 (Idx 0-14)
    board[0:15] = [1, 1, 1, 1, 1, 1, 6, 14, 12, 3, 8, 7, 10, 9, 1]
    # Row 1 (Idx 15-29)
    board[15:30] = [1, 1, 1, 1, 1, 1, 1, 20, 28, 26, 17, 22, 21, 24, 23]
    # Row 2 (Idx 30-44) -> Idx 30 is 0
    board[30:45] = [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 34, 40]
    # Row 3 (Idx 45-59)
    board[45:60] = [39, 13, 11, 33, 36, 35, 38, 37, 5, 4, 1, 1, 1, 1, 1]
    # Row 4 (Idx 60-74)
    board[60:75] = [1, 1, 1, 1, 1, 1, 1, 1, 42, 48, 47, 27, 25, 41, 44, 43]
    # Row 5 (Idx 75-89) -> 79~85 are 0s
    board[75:90] = [46, 45, 19, 18, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1] 
    
    # 나머지는 이미 1로 초기화됨
    
    # 2. 빈칸 위치 및 빠진 숫자 확인
    zero_indices = [i for i, x in enumerate(board) if x == 0]
    missing_nums = [1, 2, 15, 16, 29, 30, 31, 32]
    
    print(f"[*] 빈칸 위치(Indices): {zero_indices}")
    print(f"[*] 채워야 할 숫자: {missing_nums}")
    
    if len(zero_indices) != len(missing_nums):
        print("[!] 경고: 빈칸 개수와 숫자 개수가 맞지 않습니다. 덤프 오차일 수 있으니 진행합니다.")
        # 개수가 안 맞으면 앞쪽부터 채웁니다.
    
    # 3. 순열(Permutations) 생성 및 대입
    count = 0
    
    # 40320가지 경우의 수
    for p in itertools.permutations(missing_nums):
        count += 1
        
        # 보드에 숫자 채우기
        current_attempt = list(board)
        for i, num in enumerate(p):
            if i < len(zero_indices):
                current_attempt[zero_indices[i]] = num
        
        # 파일 저장
        with open("hakai_solution.bin", "wb") as f:
            f.write(bytes(current_attempt))
            
        # 4. 바이너리 실행 및 검증
        # subprocess로 ./hakai 실행 후 출력 확인
        try:
            # 타임아웃을 짧게 줘서 빠르게 넘깁니다.
            result = subprocess.run(["./hakai", "hakai_solution.bin"], capture_output=True, text=True, timeout=0.5)
            
            # "wrong"이 출력되지 않으면 정답일 확률 높음!
            if "wrong" not in result.stdout and "wrong" not in result.stderr:
                print(f"\n[!] 정답 발견! (시도 횟수: {count})")
                print(f"[*] 배치 결과: {p}")
                
                # 최종 플래그 계산
                import hashlib
                h = hashlib.sha256(bytes(current_attempt)).hexdigest()
                print(f"\n[★] FINAL FLAG: DH{{{h}}}")
                break
                
        except subprocess.TimeoutExpired:
            # 타임아웃이 났다는 건 무한루프(성공 로직)에 빠졌을 수도 있음
            print(f"\n[!] 타임아웃 발생 (정답 가능성 있음!) - 시도: {count}")
            import hashlib
            h = hashlib.sha256(bytes(current_attempt)).hexdigest()
            print(f"[★] FLAG Candidate: DH{{{h}}}")
            break
            
        if count % 1000 == 0:
            sys.stdout.write(f"\r[*] 진행 중... {count}/40320")
            sys.stdout.flush()

solve_final_puzzle()