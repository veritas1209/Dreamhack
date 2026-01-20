import sys

# 1. 덤프 데이터 파싱 함수 (수정됨)
def parse_dump(filename):
    constraints = {} # (y * 15 + x) -> value
    raw_bytes = bytearray()
    
    start_addr = 0x104020
    
    print(f"[*] Parsing {filename}...")
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue # 빈 줄 건너뛰기
            
            parts = line.split()
            
            # [수정] 최소 2개 이상의 요소가 없으면(주석이나 헤더 등) 건너뜀
            if len(parts) < 2:
                continue

            try:
                addr_str = parts[0]
                byte_str = parts[1]
                
                # 16진수 변환 시도 (변환 실패 시 ValueError 발생 -> except로 이동)
                curr_addr = int(addr_str, 16)
                byte_val = int(byte_str, 16)
                
                # 유효한 데이터 영역만 추출 (0x104020 부터)
                if curr_addr >= start_addr:
                    raw_bytes.append(byte_val)
            except ValueError:
                # 주석(//)이나 라벨(DAT_...) 등 16진수가 아닌 라인은 무시
                continue

    # 3바이트씩 읽어서 제약 조건 생성
    # 구조: [x_coord] [y_coord] [value]
    print(f"[*] Extracted {len(raw_bytes)} bytes. Processing constraints...")
    
    for i in range(0, len(raw_bytes), 3):
        if i + 2 >= len(raw_bytes): break
        
        x = raw_bytes[i]
        y = raw_bytes[i+1]
        val = raw_bytes[i+2]
        
        if val != 0: # 값이 0이 아니면 제약 조건
            idx = y * 15 + x
            if 0 <= idx < 225:
                constraints[val] = idx
            
    return constraints

# 2. 히다토(Number Snake) Solver (DFS with Pruning)
class HidatoSolver:
    def __init__(self, constraints):
        self.grid = [0] * 225
        self.constraints = constraints # Value -> Index
        self.fixed_indices = {v: k for k, v in constraints.items()} # Index -> Value
        
        # 그리드에 고정 값 미리 채우기
        for val, idx in constraints.items():
            self.grid[idx] = val
            
    def get_neighbors(self, idx):
        r, c = idx // 15, idx % 15
        neighbors = []
        for dr in [-1, 0, 1]:
            for dc in [-1, 0, 1]:
                if dr == 0 and dc == 0: continue
                nr, nc = r + dr, c + dc
                if 0 <= nr < 15 and 0 <= nc < 15:
                    neighbors.append(nr * 15 + nc)
        return neighbors

    def solve(self, curr_val, curr_idx):
        # 목표 도달
        if curr_val == 225:
            return True

        next_val = curr_val + 1

        # 가지치기 (Pruning): 다음 고정된 숫자까지의 거리가 너무 멀면 포기
        for target_val in range(next_val, 226):
            if target_val in self.constraints:
                target_idx = self.constraints[target_val]
                tr, tc = target_idx // 15, target_idx % 15
                cr, cc = curr_idx // 15, curr_idx % 15
                dist = max(abs(tr - cr), abs(tc - cc))
                if dist > (target_val - curr_val):
                    return False # 도달 불가능
                break 

        # Case 1: 다음 숫자의 위치가 이미 정해져 있는 경우
        if next_val in self.constraints:
            next_idx = self.constraints[next_val]
            if next_idx in self.get_neighbors(curr_idx):
                return self.solve(next_val, next_idx)
            else:
                return False 

        # Case 2: 다음 숫자의 위치가 정해져 있지 않은 경우
        neighbors = self.get_neighbors(curr_idx)
        
        for n_idx in neighbors:
            if self.grid[n_idx] == 0: # 빈 칸
                self.grid[n_idx] = next_val
                if self.solve(next_val, n_idx):
                    return True
                self.grid[n_idx] = 0 # Backtracking
        
        return False

# 3. 메인 실행 로직
def main():
    dump_file = "data.txt" 
    
    try:
        constraints = parse_dump(dump_file)
    except FileNotFoundError:
        print(f"Error: '{dump_file}' not found.")
        return

    print(f"[*] Loaded {len(constraints)} constraints.")
    
    if 1 not in constraints:
        print("Error: Start position (1) not found in constraints.")
        # 디버깅용: 추출된 제약조건 일부 출력
        # print("Debug - First 10 constraints:", list(constraints.items())[:10])
        return
        
    start_idx = constraints[1]
    solver = HidatoSolver(constraints)
    
    print(f"[*] Starting solver from index {start_idx}...")
    if solver.solve(1, start_idx):
        print("[+] Solution Found!")
        
        with open("solution.bin", "wb") as f:
            f.write(bytes(solver.grid))
        print("[+] Saved to 'solution.bin'.")
        print("[*] Run command: ./vernichtet solution.bin")
    else:
        print("[-] No solution found.")

if __name__ == "__main__":
    main()