import time
from collections import defaultdict

def load_clues_from_file(filename):
    """파일에서 단서 데이터를 로드"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        clues = []
        for line in lines:
            line = line.strip()
            if line:  # 빈 줄이 아닌 경우
                # 공백으로 구분된 숫자들을 파싱
                numbers = [int(x) for x in line.split() if x.isdigit()]
                if numbers:  # 숫자가 있는 경우만 추가
                    clues.append(numbers)
        return clues
    except FileNotFoundError:
        print(f"파일 '{filename}'을 찾을 수 없습니다.")
        return None
    except Exception as e:
        print(f"파일 '{filename}' 로딩 중 오류: {e}")
        return None

def generate_line_possibilities(length, clues):
    """주어진 길이와 단서로 가능한 모든 라인 패턴을 생성 (최적화)"""
    if not clues:
        return [[0] * length]
    
    # 메모이제이션을 위한 캐시
    cache = {}
    
    def solve(pos, block_idx, current_pattern):
        cache_key = (pos, block_idx, tuple(current_pattern))
        if cache_key in cache:
            return cache[cache_key]
        
        if block_idx == len(clues):
            result = [current_pattern + [0] * (length - len(current_pattern))]
            cache[cache_key] = result
            return result
        
        results = []
        block_size = clues[block_idx]
        remaining_blocks = clues[block_idx + 1:]
        min_space_needed = sum(remaining_blocks) + len(remaining_blocks)
        max_start = length - block_size - min_space_needed
        
        for start in range(pos, max_start + 1):
            new_pattern = current_pattern + [0] * (start - len(current_pattern))
            new_pattern.extend([1] * block_size)
            if block_idx < len(clues) - 1:
                new_pattern.append(0)
                results.extend(solve(len(new_pattern), block_idx + 1, new_pattern))
            else:
                results.extend(solve(len(new_pattern), block_idx + 1, new_pattern))
        
        cache[cache_key] = results
        return results
    
    return solve(0, 0, [])

def is_compatible(line, pattern):
    """라인과 패턴이 호환되는지 확인"""
    for i in range(len(line)):
        if line[i] != -1 and line[i] != pattern[i]:
            return False
    return True

def apply_line_solving_optimized(line, clues, possibilities_cache=None):
    """최적화된 라인 단위 제약 전파"""
    if possibilities_cache is None:
        possibilities_cache = {}
    
    cache_key = (len(line), tuple(clues))
    if cache_key not in possibilities_cache:
        possibilities_cache[cache_key] = generate_line_possibilities(len(line), clues)
    
    possibilities = possibilities_cache[cache_key]
    valid_possibilities = [p for p in possibilities if is_compatible(line, p)]
    
    if not valid_possibilities:
        return None, possibilities_cache
    
    # 모든 가능성에서 공통된 셀 찾기
    result = line[:]
    for i in range(len(line)):
        values = set(p[i] for p in valid_possibilities)
        if len(values) == 1:
            result[i] = values.pop()
    
    return result, possibilities_cache

def solve_nonogram_optimized(row_clues, col_clues):
    """최적화된 노노그램 솔버"""
    rows = len(row_clues)
    cols = len(col_clues)
    
    print(f"노노그램 크기: {rows} x {cols}")
    print("초기화 중...")
    
    # 그리드 초기화
    grid = [[-1 for _ in range(cols)] for _ in range(rows)]
    
    # 캐시 초기화
    row_cache = {}
    col_cache = {}
    
    def print_progress(iteration, total_changes):
        if iteration % 10 == 0 or total_changes > 0:
            filled = sum(1 for r in range(rows) for c in range(cols) if grid[r][c] != -1)
            total = rows * cols
            progress = (filled / total) * 100
            print(f"반복 {iteration}: {filled}/{total} 셀 확정 ({progress:.1f}%) - 변경: {total_changes}")
    
    print("\n=== 제약 전파 시작 ===")
    iteration = 0
    max_iterations = 200
    
    while iteration < max_iterations:
        changes = 0
        iteration += 1
        
        # 행 처리
        for r in range(rows):
            old_row = grid[r][:]
            new_row, row_cache = apply_line_solving_optimized(grid[r], row_clues[r], row_cache)
            if new_row is None:
                print(f"모순 발견 - 행 {r}")
                return None
            if new_row != old_row:
                grid[r] = new_row
                changes += sum(1 for i in range(cols) if old_row[i] != new_row[i])
        
        # 열 처리
        for c in range(cols):
            col = [grid[r][c] for r in range(rows)]
            old_col = col[:]
            new_col, col_cache = apply_line_solving_optimized(col, col_clues[c], col_cache)
            if new_col is None:
                print(f"모순 발견 - 열 {c}")
                return None
            if new_col != old_col:
                for r in range(rows):
                    grid[r][c] = new_col[r]
                changes += sum(1 for i in range(rows) if old_col[i] != new_col[i])
        
        print_progress(iteration, changes)
        
        if changes == 0:
            print(f"\n제약 전파 완료! ({iteration}번 반복)")
            break
    
    # 완성도 확인
    filled = sum(1 for r in range(rows) for c in range(cols) if grid[r][c] != -1)
    total = rows * cols
    completion = (filled / total) * 100
    
    print(f"제약 전파 결과: {filled}/{total} 셀 확정 ({completion:.1f}%)")
    
    if completion < 100:
        print("\n=== 백트래킹 시작 ===")
        if not backtrack_optimized(grid, row_clues, col_clues, row_cache, col_cache):
            print("해를 찾을 수 없습니다.")
            return None
    
    return grid

def backtrack_optimized(grid, row_clues, col_clues, row_cache, col_cache):
    """최적화된 백트래킹"""
    rows = len(grid)
    cols = len(grid[0])
    
    def is_complete():
        for r in range(rows):
            for c in range(cols):
                if grid[r][c] == -1:
                    return False
        return True
    
    def find_best_cell():
        """가장 제약이 많은 셀 찾기"""
        best_cell = None
        min_possibilities = float('inf')
        
        for r in range(rows):
            for c in range(cols):
                if grid[r][c] == -1:
                    # 행과 열의 제약 확인
                    row_constraints = 0
                    col_constraints = 0
                    
                    # 간단한 휴리스틱: 주변 확정된 셀 개수
                    for cc in range(cols):
                        if grid[r][cc] != -1:
                            row_constraints += 1
                    for rr in range(rows):
                        if grid[rr][c] != -1:
                            col_constraints += 1
                    
                    total_constraints = row_constraints + col_constraints
                    if total_constraints < min_possibilities:
                        min_possibilities = total_constraints
                        best_cell = (r, c)
        
        return best_cell
    
    if is_complete():
        return True
    
    cell = find_best_cell()
    if cell is None:
        return True
    
    r, c = cell
    
    # 0과 1 시도 (1을 먼저 시도)
    for value in [1, 0]:
        grid[r][c] = value
        
        # 빠른 유효성 검사
        if is_valid_partial(grid, row_clues, col_clues, r, c):
            if backtrack_optimized(grid, row_clues, col_clues, row_cache, col_cache):
                return True
        
        grid[r][c] = -1
    
    return False

def is_valid_partial(grid, row_clues, col_clues, changed_r, changed_c):
    """부분적 유효성 검사 (변경된 행/열만)"""
    rows = len(grid)
    cols = len(grid[0])
    
    # 변경된 행 검사
    row = grid[changed_r]
    if -1 not in row:  # 행이 완성된 경우
        if not matches_clue(row, row_clues[changed_r]):
            return False
    
    # 변경된 열 검사
    col = [grid[r][changed_c] for r in range(rows)]
    if -1 not in col:  # 열이 완성된 경우
        if not matches_clue(col, col_clues[changed_c]):
            return False
    
    return True

def matches_clue(line, clue):
    """라인이 단서와 일치하는지 확인"""
    blocks = []
    current_block = 0
    
    for cell in line:
        if cell == 1:
            current_block += 1
        else:
            if current_block > 0:
                blocks.append(current_block)
                current_block = 0
    
    if current_block > 0:
        blocks.append(current_block)
    
    return blocks == clue

def print_grid(grid, save_to_file=True):
    """그리드를 출력하고 선택적으로 파일에 저장"""
    if grid is None:
        print("해가 없습니다.")
        return
    
    result = []
    for row in grid:
        line = ''.join('██' if cell == 1 else '  ' for cell in row)
        result.append(line)
        print(line)
    
    if save_to_file:
        with open('nonogram_result.txt', 'w', encoding='utf-8') as f:
            for line in result:
                f.write(line + '\n')
        print("\n결과가 'nonogram_result.txt' 파일에 저장되었습니다.")

if __name__ == "__main__":
    # 파일 경로 설정
    row_file_path = r"C:\Users\hajin\hacking_study\dreamhack\2276\row_clues.txt"
    col_file_path = r"C:\Users\hajin\hacking_study\dreamhack\2276\col_clues.txt"
    
    # 시작 시간 기록
    start_time = time.time()
    
    # 데이터 로드
    print("=== 데이터 로딩 ===")
    print(f"행 데이터: {row_file_path}")
    print(f"열 데이터: {col_file_path}")
    
    row_clues = load_clues_from_file(row_file_path)
    col_clues = load_clues_from_file(col_file_path)

    if row_clues is None:
        print("ERROR: row_clues.txt 파일을 찾을 수 없습니다!")
        exit(1)

    if col_clues is None:
        print("ERROR: col_clues.txt 파일을 찾을 수 없습니다!")
        exit(1)

    print(f"로드된 행 데이터: {len(row_clues)}줄")
    print(f"로드된 열 데이터: {len(col_clues)}줄")
    
    # 데이터 유효성 검사
    if len(row_clues) == 0 or len(col_clues) == 0:
        print("유효하지 않은 데이터입니다.")
        exit(1)
    
    print("\n=== 노노그램 풀이 시작 ===")
    
    try:
        solution = solve_nonogram_optimized(row_clues, col_clues)
        
        elapsed = time.time() - start_time
        print(f"\n=== 완료! 소요시간: {elapsed:.2f}초 ===")
        
        if solution:
            print("\n=== 노노그램 결과 ===")
            print_grid(solution)
        else:
            print("해를 찾을 수 없습니다.")
            
    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n중단되었습니다. (경과시간: {elapsed:.2f}초)")
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"오류가 발생했습니다: {e} (경과시간: {elapsed:.2f}초)")