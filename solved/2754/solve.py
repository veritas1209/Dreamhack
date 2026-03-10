def solve():
    # 1. GDB 등에서 덤프 뜬 world 배열 로드 (177,147 bytes)
    try:
        with open("world.bin", "rb") as f:
            world = f.read()
    except FileNotFoundError:
        print("world.bin 파일이 필요합니다. GDB에서 덤프해주세요.")
        return

    # 각 차원별 인덱스 증가율
    multipliers = [1, 3, 9, 27, 81, 243, 729, 2187, 6561, 19683, 59049]
    
    # 이동 방향에 따른 문자 맵핑
    moves = {
        (10, -1): 'a', (10, 1): 'b',
        (9, -1): 'c',  (9, 1): 'd',
        (8, -1): 'e',  (8, 1): 'f',
        (7, -1): 'g',  (7, 1): 'h',
        (6, -1): 'i',  (6, 1): 'j',
        (5, -1): 'k',  (5, 1): 'l',
        (4, -1): 'm',  (4, 1): 'n',
        (3, -1): 'o',  (3, 1): 'p',
        (2, -1): 'q',  (2, 1): 'r',
        (1, -1): 's',  (1, 1): 't',
        (0, -1): 'u',  (0, 1): 'v',
    }

    # 시작 좌표는 중앙인 (1, 1, ... 1)
    start_pos = [1] * 11
    start_idx = sum(start_pos[i] * multipliers[i] for i in range(11))
    
    # DFS 스택: (현재 좌표 리스트, 누적된 문자열 경로, 방문한 인덱스 set)
    stack = [(start_pos, "", {start_idx})]
    
    while stack:
        pos, path, visited = stack.pop()
        
        # 84번 올바른 길로 움직였다면 정답
        if len(path) == 84:
            print("[+] Found Input String:", path)
            return path
            
        # 11개의 차원을 모두 탐색
        for dim in range(11):
            for direction in [-1, 1]:
                new_pos = list(pos)
                new_pos[dim] += direction
                
                # 좌표가 0~2 사이를 벗어나면 스킵 (range 조건)
                if not (0 <= new_pos[dim] <= 2):
                    continue
                    
                # 새로운 1차원 배열 인덱스 계산
                idx = sum(new_pos[i] * multipliers[i] for i in range(11))
                
                # 다음 칸이 1이고 방문하지 않은 곳일 때만 이동
                if world[idx] == 1 and idx not in visited:
                    char = moves[(dim, direction)]
                    new_visited = set(visited)
                    new_visited.add(idx)
                    stack.append((new_pos, path + char, new_visited))

    print("[-] 경로를 찾지 못했습니다.")

if __name__ == "__main__":
    solve()