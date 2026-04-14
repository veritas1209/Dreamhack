def lcg(s, N):
    return (s * 3 + 1337) % N

def parse_and_export():
    # 1. 파일 읽기
    with open("output.txt", "r", encoding="utf-8") as f:
        raw_text = f.read()

    # 2. 에러의 원인이던 정규식을 아예 빼버리고, 단순 반복문으로 태그 제거
    for i in range(1, 100):
        raw_text = raw_text.replace(f"", "")
        raw_text = raw_text.replace(f"", "")

    # 줄바꿈 기준으로 쪼개기
    lines = raw_text.split('\n')
    merged_lines = []

    # 3. 제멋대로 잘려있는 줄들을 지능적으로 이어붙이기
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        if line.startswith("="):
            # 이전 줄이 "[DEBUG] e" 였는데 이번 줄이 "=" 로 시작하면 합침
            merged_lines[-1] = merged_lines[-1] + " " + line
        elif line.startswith("e ="):
            # 이전 줄이 "[DEBUG]" 였는데 이번 줄이 "e =" 로 시작하면 합침
            merged_lines[-1] = merged_lines[-1] + " " + line
        elif merged_lines and merged_lines[-1].endswith("="):
            # 이전 줄이 "[DEBUG] e =" 로 끝났는데 이번 줄이 숫자면 합침
            merged_lines[-1] = merged_lines[-1] + " " + line
        elif merged_lines and merged_lines[-1] == "[DEBUG]":
            # 이전 줄이 "[DEBUG]" 로만 끝났을 때 안전하게 합침
            merged_lines[-1] = merged_lines[-1] + " " + line
        else:
            merged_lines.append(line)

    N = None
    data = []
    e_prev = None

    # 4. 데이터 추출
    for line in merged_lines:
        if line.startswith('N ='):
            N = int(line.split('=')[1].strip())
        elif line.startswith('[DEBUG] e ='):
            e_str = line.split('=')[1].strip()
            if e_str: 
                e_prev = int(e_str)
        elif line.isdigit():
            r_curr = int(line)
            
            if e_prev is not None:
                actual_exponent = lcg(e_prev, N)
                data.append((actual_exponent, r_curr))
                e_prev = None

    print(f"[*] 총 {len(data)}개의 (e, r) 쌍을 성공적으로 파싱했습니다!")

    # 5. 파이썬 파일로 출력
    with open("parsed_data.py", "w", encoding="utf-8") as f:
        f.write(f"N = {N}\n\n")
        f.write("data = [\n")
        for i, (e, r) in enumerate(data):
            f.write(f"    ({i}, {e}, {r}),\n")
        f.write("]\n")
        
    print("[*] 'parsed_data.py' 파일이 생성되었습니다! 완료!")

if __name__ == "__main__":
    parse_and_export()