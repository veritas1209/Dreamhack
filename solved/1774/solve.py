from collections import deque

# 1. ELF 파일에서 직접 미로 데이터(15,625 바이트) 추출
FILE_NAME = 'chall'
OFFSET = 0x3060
MAZE_SIZE = 25 * 25 * 25 # 15,625

with open(FILE_NAME, 'rb') as f:
    f.seek(OFFSET)
    maze_data = f.read(MAZE_SIZE)

# 2. 이동 방향 매핑 (문자: (dx, dy, dz))
moves = {
    'K': (1, 0, 0),
    '9': (-1, 0, 0),
    'z': (0, 1, 0),
    '7': (0, -1, 0),
    '2': (0, 0, 1),
    's': (0, 0, -1)
}

# 3. BFS 탐색
start = (24, 12, 12)
target = (0, 12, 12)

def solve_maze(maze):
    # queue: (x, y, z, 현재까지의 경로 문자열)
    queue = deque([(start[0], start[1], start[2], "")])
    visited = set()
    visited.add(start)

    while queue:
        x, y, z, path = queue.popleft()

        # 도착지에 도달하면 경로(플래그) 반환
        if (x, y, z) == target:
            return path

        for char, (dx, dy, dz) in moves.items():
            nx, ny, nz = x + dx, y + dy, z + dz

            # 맵 범위 검사 (0 ~ 24)
            if 0 <= nx <= 24 and 0 <= ny <= 24 and 0 <= nz <= 24:
                # 1차원 배열 인덱스 계산 (y * 25 + z * 625 + x)
                idx = ny * 25 + nz * 625 + nx
                
                # 방문하지 않았고, 벽(1)이 아닌 경우 이동 (바이트 값이 1이 아닌지 확인)
                if maze[idx] != 1 and (nx, ny, nz) not in visited:
                    visited.add((nx, ny, nz))
                    queue.append((nx, ny, nz, path + char))
                    
    return "Path not found"

# 실행 및 플래그 출력
print("[*] 미로 탐색을 시작합니다...")
flag_path = solve_maze(maze_data)
print(f"[*] 플래그 획득: DH{{{flag_path}}}")